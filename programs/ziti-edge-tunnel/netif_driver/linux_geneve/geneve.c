/*
 Copyright 2021 NetFoundry Inc.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

#include <linux/if_tun.h>
#include <stdlib.h>
#include <netif_shim.h>
#include <ziti/ziti_log.h>
#include <lwip/udp.h>
#include "lwip/priv/tcp_priv.h"
#include "geneve.h"

/* max ipv4 MTU */
#define BUFFER_SIZE 9000


static int geneve_close(netif_handle geneve) {
    uv_udp_recv_stop(&geneve->udp_handle_in);
    uv_close((uv_handle_t *) geneve, NULL);
}

struct geneve_packet_s {
    uv_buf_t buf[2];
    struct geneve_flow_s *matched_flow_value;
};

struct geneve_timeout_ctx_s {
    netif_handle geneve;
    struct geneve_flow_s *flow_info;
};

static void geneve_timeout_cb(uv_timer_t *geneve) {

    struct geneve_timeout_ctx_s *gt_ctx = geneve->data;
    ZITI_LOG(INFO, "The flow %s has reached a timeout and will be deleted now!!!", gt_ctx->flow_info->search_flow_key);
    uv_close((uv_handle_t *) &gt_ctx->flow_info->udp_handle_out, NULL);
    model_map_remove(&gt_ctx->geneve->flow_list, gt_ctx->flow_info->search_flow_key);
    size_t map_size = model_map_size(&gt_ctx->geneve->flow_list);
    ZITI_LOG(DEBUG, "The record with key %s has been deleted from the flow table,"
                    " and the table size is at %zu now.", gt_ctx->flow_info->search_flow_key, map_size);
    free(gt_ctx);
}

static void read_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    buf->base = malloc(BUFFER_SIZE);
    buf->len = BUFFER_SIZE;
    // TODO throttle to limit the memory usage
}

static void write_status_cb(uv_udp_send_t *req, int status) {

    ZITI_LOG(DEBUG, "Geneve write completed and status %d", status);
    struct geneve_packet_s *g_pkt = req->data;
    free(g_pkt->buf[0].base);
    free(g_pkt->buf[1].base);
    free(g_pkt);
    free(req);

}

static void geneve_overhead_pack(struct geneve_hdr *g_hdr, const void *buf, uint8_t *received_flow_id) {

    /* Creating the geneve header for return packets */
    g_hdr->ver = GENEVE_VER;
    g_hdr->oam = 0;
    g_hdr->critical = 0;
    g_hdr->rsvd1 = 0;
    g_hdr->vni[0] = 0;
    g_hdr->vni[1] = 0;
    g_hdr->vni[2] = 0;
    g_hdr->proto_type = lwip_htons(ETH_P_IP);
    g_hdr->rsvd2 = 0;
    g_hdr->options[0].opt_class = htons(0x0108);
    g_hdr->options[0].type = 1;
    g_hdr->options[0].r1 = 0;
    g_hdr->options[0].r2 = 0;
    g_hdr->options[0].r3 = 0;
    memcpy(&g_hdr->options[0].opt_data[0], &received_flow_id[12], 8 * sizeof(uint8_t));
    g_hdr->options[0].length = 2;
    g_hdr->options[1].opt_class = htons(0x0108);
    g_hdr->options[1].type = 2;
    g_hdr->options[1].r1 = 0;
    g_hdr->options[1].r2 = 0;
    g_hdr->options[1].r3 = 0;
    memcpy(&g_hdr->options[1].opt_data[0], &received_flow_id[24], 8 * sizeof(uint8_t));
    g_hdr->options[1].length = 2;
    g_hdr->options[2].opt_class = htons(0x0108);
    g_hdr->options[2].type = 3;
    g_hdr->options[2].r1 = 0;
    g_hdr->options[2].r2 = 0;
    g_hdr->options[2].r3 = 0;
    memcpy(&g_hdr->options[2].opt_data[0], &received_flow_id[36], 4 * sizeof(uint8_t));
    g_hdr->options[2].length = 1;
    g_hdr->opt_len = 32 >> 2;

}

static void parse_ipheader(struct inner_ip_hdr_info *i_hdr, const void *buf) {
    /* TODO Can the TSDK provide this function*/
    /* Initialize IP variables */
    u16_t iphdr_hlen;
    char ip_version = IPH_V((struct ip_hdr *)(buf));

    /* filter IP header to get inner IP addresses */
    switch (ip_version) {
        case 4: {
            struct ip_hdr *iphdr = (struct ip_hdr*) (buf);
            iphdr_hlen = IPH_HL_BYTES(iphdr);
            i_hdr->proto_type = IPH_PROTO(iphdr);
            ip_addr_copy_from_ip4(i_hdr->src, iphdr->src);
            ip_addr_copy_from_ip4(i_hdr->dst, iphdr->dest);
        }
            break;
        case 6: {
            struct ip6_hdr *iphdr = (struct ip6_hdr*) (buf);
            iphdr_hlen = IP6_HLEN;
            i_hdr->proto_type = IP6H_NEXTH(iphdr);
            ip_addr_copy_from_ip6_packed(i_hdr->src, iphdr->src);
            ip_addr_copy_from_ip6_packed(i_hdr->dst, iphdr->dest);
        }
            break;
        default:
            ZITI_LOG(INFO, "unsupported IP protocol version: %d", ip_version);
            return;
    }

    /* filter TCP/UDP header to get ports */
    switch (i_hdr->proto_type) {
        case IPPROTO_TCP: {
            struct tcp_hdr *tcphdr = (struct tcp_hdr *)(buf + iphdr_hlen);
            i_hdr->src_p = tcphdr->src;
            i_hdr->dst_p = tcphdr->dest;
            i_hdr->flags = TCPH_FLAGS(tcphdr);
            ZITI_LOG(DEBUG, "TCP Flag: %X", i_hdr->flags);
        }
            break;
        case IPPROTO_UDP: {
            struct udp_hdr *udphdr = (struct udp_hdr *)(buf + iphdr_hlen);
            i_hdr->src_p = udphdr->src;
            i_hdr->dst_p = udphdr->dest;
        }
            break;
        default:
            ZITI_LOG(INFO, "unsupported protocol type: %d", i_hdr->proto_type);
            return;
    }

    /* Log the connection details in debug mode */
    char src_str[IPADDR_STRLEN_MAX];
    ipaddr_ntoa_r(&i_hdr->src, src_str, sizeof(src_str));
    if (i_hdr->proto_type == 6) {
        ZITI_LOG(DEBUG, "received TCP datagram %s:%d->%s:%d",
                 src_str, ntohs(i_hdr->src_p),
                 ipaddr_ntoa(&i_hdr->dst), ntohs(i_hdr->dst_p));
    }
    if (i_hdr->proto_type == 17) {
        ZITI_LOG(DEBUG, "received UDP datagram %s:%d->%s:%d",
                 src_str, ntohs(i_hdr->src_p),
                 ipaddr_ntoa(&i_hdr->dst), ntohs(i_hdr->dst_p));
    }
}

void geneve_udp_read(uv_udp_t *req, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags) {

    /* just log error */
    if (nread < 0) {
        ZITI_LOG(ERROR, "Read error %s", uv_err_name(nread));
    }

    /*  return if read byte length is 0 or less  */
    if ( nread <= 0) {
        free(buf->base);
        return;
    }

    /* read receive geneve version and header length */
    int gen_ver = buf->base[0] & 0xC0 >> 6;
    int gen_hdr_len = buf->base[0] & 0x3F;
    ZITI_LOG(DEBUG, "Received Geneve version is %d", gen_ver);
    ZITI_LOG(DEBUG, "Received Geneve header length is %d bytes", gen_hdr_len * 4);

    /* if the length is not equal to 32 bytes */
    if (gen_hdr_len != AWS_GNV_HDR_OPT_LEN / 4 && gen_ver != GENEVE_VER ){
        ZITI_LOG(ERROR, "Geneve header length:version error %d:%d", gen_hdr_len, gen_ver);
        free(buf->base);
        return;
    }

    /* Initializing map, driver, handle */
    netif_driver_t *driver = req->data;
    netif_handle geneve = driver->handle;

    /* Retrieve Network info from ip/transport headers */
    struct inner_ip_hdr_info *i_hdr = calloc(1, sizeof(struct inner_ip_hdr_info));
    parse_ipheader(i_hdr, buf->base + AWS_GNV_HDR_LEN);
    if (i_hdr == NULL) {
        free(buf->base);
        free(i_hdr);
        return;
    }

    /*
       build flow key with the order expected in return packet i.e.:
       [0]      Transport Type          <- TCP/UDP
       [1:4]    Return Source Ip        <- Received Destination Ip
       [5:8]    Return Destination Ip   <- Received Source Ip
       [9:10]   Return Source Port      <- Received Destination Port
       [11:12]  Return Destination Port <- Received Source Port
     */
    u8_t flow_key_byte[13];
    memcpy(&flow_key_byte[0], &i_hdr->proto_type, 1 * sizeof(uint8_t));
    memcpy(&flow_key_byte[1], &i_hdr->dst.u_addr.ip4.addr, 4 * sizeof(uint8_t));
    memcpy(&flow_key_byte[5], &i_hdr->src.u_addr.ip4.addr, 4 * sizeof(uint8_t));
    memcpy(&flow_key_byte[9], &i_hdr->dst_p, 2 * sizeof(uint8_t));
    memcpy(&flow_key_byte[11], &i_hdr->src_p, 2 * sizeof(uint8_t));

    /* Convert to string */
    char search_flow_key[27];
    for (int i = 0; i < 13; i++) {
        sprintf(&search_flow_key[i*2], "%02x", flow_key_byte[i]);
    }
    search_flow_key[26] = '\0';
    ZITI_LOG(DEBUG, "flow key is %s", search_flow_key);

    /* Check if key exists, no need for new entry or outbound handle */
    struct geneve_flow_s *flow_info = model_map_get(&geneve->flow_list, search_flow_key);
    if (flow_info == NULL) {

        /* Initialize flow struct */
        flow_info = calloc(1, sizeof(struct geneve_flow_s));

        /* Fill in values for flow_info struct */;
        flow_info->send_address = *(struct sockaddr_in *) addr;
        flow_info->send_address.sin_port = lwip_htons(GENEVE_UDP_PORT);
        flow_info->bind_address = *(struct sockaddr_in *) addr;
        inet_aton(IP_LOCAL_BIND, &flow_info->bind_address.sin_addr);
        memcpy(&flow_info->id[0], &buf->base[0], 40 * sizeof(uint8_t));
        memcpy(&flow_info->search_flow_key, search_flow_key, 27);

        /* Initialize flow timer */
        flow_info->idle_timeout = 120000;
        uv_timer_init(geneve->loop, &flow_info->conn_timer);
        struct geneve_timeout_ctx_s *gt_ctx = calloc(1, sizeof(struct geneve_timeout_ctx_s));
        flow_info->conn_timer.data = gt_ctx;
        gt_ctx->geneve = geneve;
        gt_ctx->flow_info = flow_info;

        /* Copy Geneve header info into flow_list map */
        model_map_set(&geneve->flow_list, search_flow_key, flow_info);
        size_t map_size = model_map_size(&geneve->flow_list);

        ZITI_LOG(INFO, "The new flow %s has been created!!!", search_flow_key);
        ZITI_LOG(DEBUG, "The flow table size has increased to %zu.", map_size);
        ZITI_LOG(DEBUG, "Geneve (2) Send Address %s:%d", inet_ntoa(flow_info->send_address.sin_addr), htons ( flow_info->send_address.sin_port));
        ZITI_LOG(DEBUG, "Geneve (2) Bind Address %s:%d", inet_ntoa(flow_info->bind_address.sin_addr), htons ( flow_info->bind_address.sin_port));

        /* Initialize outbound handle */
        if (uv_udp_init(geneve->loop, &flow_info->udp_handle_out)) {
            ZITI_LOG(ERROR, "Failed to initialize uv UDP handle out for geneve");
        }
        if (uv_udp_bind(&flow_info->udp_handle_out, (const struct sockaddr *) &flow_info->bind_address,UV_UDP_REUSEADDR)) {
            ZITI_LOG(ERROR, "Could not add netlink socket to uv UDP handle out for geneve");
        }
    }

    /* Restart the flow timer */
    uv_timer_start(&flow_info->conn_timer, geneve_timeout_cb, flow_info->idle_timeout, 0);

    /* Let lwip process the packet */
    on_packet(buf->base + 40, nread - 40, netif_default);
    free(buf->base);
    free(i_hdr);
}

void geneve_write(netif_handle geneve, const void *buf, size_t len) {

    /* read flow map  with received key to get flow details to build the geneve header */
    u8_t received_flow_key_byte[13];
    memcpy(&received_flow_key_byte[0], &buf[9], 1*sizeof(uint8_t));
    memcpy(&received_flow_key_byte[1], &buf[12], 12*sizeof(uint8_t));

    /* Convert to string */
    struct geneve_packet_s *g_pkt = calloc(1, sizeof(struct geneve_packet_s));
    char search_flow_key[27];
    for (int i = 0; i < 13; i++) {
        sprintf(&search_flow_key[i*2], "%02x", received_flow_key_byte[i]);
    }
    search_flow_key[26] = '\0';
    ZITI_LOG(DEBUG, "The received search flow key is %s", search_flow_key);

    /* Retrieve flow_info based on the received key */
    g_pkt->matched_flow_value = model_map_get(&geneve->flow_list, search_flow_key);
    if (g_pkt->matched_flow_value != NULL) {

        /* Build the geneve header */
        struct geneve_hdr *g_hdr = calloc(1, sizeof(struct geneve_hdr));
        geneve_overhead_pack(g_hdr, buf, g_pkt->matched_flow_value->id);
        size_t map_size = model_map_size(&geneve->flow_list);
        ZITI_LOG(DEBUG, "The flow table size is %zu", map_size);

        /* Combine 2 buffs into one contiguous geneve packet (header plus ip4 payload) to be sent out */
        g_pkt->buf[0].base = (char*) g_hdr;
        g_pkt->buf[0].len = sizeof(struct geneve_hdr) - 4;
        g_pkt->buf[1].base = malloc(len);
        memcpy(g_pkt->buf[1].base, buf, len);
        g_pkt->buf[1].len = len;

        /* Initializing req to use in the callback function */
        uv_udp_send_t *send_req = malloc(sizeof(uv_udp_send_t));
        send_req->data = g_pkt;

        /* Send the geneve packet out */
        ZITI_LOG(DEBUG, "Geneve (2) Send Address %s:%d", inet_ntoa( g_pkt->matched_flow_value->send_address.sin_addr), htons (g_pkt->matched_flow_value->send_address.sin_port));
        ZITI_LOG(DEBUG, "Geneve (2) Bind Address %s:%d", inet_ntoa( g_pkt->matched_flow_value->bind_address.sin_addr), htons (g_pkt->matched_flow_value->bind_address.sin_port));

        /* Restart the flow timer */
        uv_timer_start(&g_pkt->matched_flow_value->conn_timer, geneve_timeout_cb, g_pkt->matched_flow_value->idle_timeout, 0);

        /* send the geneve response back */
        uv_udp_send(send_req, &g_pkt->matched_flow_value->udp_handle_out, g_pkt->buf, 2, (const struct sockaddr*) &g_pkt->matched_flow_value->send_address, write_status_cb);

    } else {
        ZITI_LOG(ERROR, "The receive flow key %s does not exist.", search_flow_key);
        free(g_pkt);
    }
}

netif_driver geneve_open(uv_loop_t *loop, char *error, size_t error_len) {

    struct netif_handle_s *geneve = calloc(1, sizeof(struct netif_handle_s));
    geneve->loop = loop;
    struct sockaddr_in geneve_addr;

    /* Fill in the struct sockaddr_in with ip and port to bind to */
    uv_ip4_addr(IP_LOCAL_BIND, GENEVE_UDP_PORT, &geneve_addr);

    /* Add geneve socket to event loop */
    if (uv_udp_init(geneve->loop, &geneve->udp_handle_in)) {
        ZITI_LOG(ERROR, "Failed to initialize uv UDP handle in for geneve");
        return NULL;
    }

    /* Initialized memory for the driver struct */
    struct netif_driver_s *driver = calloc(1, sizeof(struct netif_driver_s));

    if (uv_udp_bind(&geneve->udp_handle_in, (const struct sockaddr *) &geneve_addr, UV_UDP_REUSEADDR)) {
        ZITI_LOG(ERROR, "Could not add netlink socket to uv geneve");
        return NULL;
    }
    ZITI_LOG(INFO, "Geneve UDP Listen Socket initialized successfully to %s:%d", inet_ntoa(geneve_addr.sin_addr), htons (geneve_addr.sin_port));

    /* udp handle to pass pointer to on_packet */
    geneve->udp_handle_in.data = driver;

    if (uv_udp_recv_start(&geneve->udp_handle_in, read_alloc_cb, geneve_udp_read)) {
        ZITI_LOG(ERROR, "Could not start receiving netlink packets for geneve");
        return NULL;
    }

    /* Initialize driver call backs */
    driver->handle = geneve;
    driver->write = (netif_write_cb) geneve_write;
    driver->close = geneve_close;

    return driver;
}