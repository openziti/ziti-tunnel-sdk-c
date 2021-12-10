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

#include <sys/ioctl.h>
#include <sys/wait.h>
//#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <netif_shim.h>

#include <ziti/ziti_log.h>
#include <ziti/ziti_dns.h>
#include <stdbool.h>
#include <lwip/inet_chksum.h>
#include <lwip/ip4_addr.h>
#include <lwip/ip4.h>
#include <lwip/udp.h>
#include "lwip/priv/tcp_priv.h"

#include "geneve.h"

/* max ipv4 MTU */
#define BUFFER_SIZE 9000

static int geneve_close(netif_handle geneve) {
    uv_udp_recv_stop(&geneve->udp_handle_in);
    uv_close((uv_handle_t *) geneve, NULL);
}

static void read_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    buf->base = malloc(BUFFER_SIZE);
    buf->len = BUFFER_SIZE;
    // TODO throttle to limit the memory usage
}

static void write_status_cb(uv_udp_send_t *req, int status) {

    ZITI_LOG(INFO, "Geneve write completed and status %d", status);
    struct geneve_packet *g_pkt = req->data;
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
       [0:3]    Return Source Ip        <- Received Destination Ip
       [4:7]    Return Destination Ip   <- Received Source Ip
       [8:9]    Return Source Port      <- Received Destination Port
       [10:11]  Return Destination Port <- Received Source Port
     */
    u8_t flow_key_byte[13];
    memcpy(&flow_key_byte[0], &i_hdr->proto_type, 1 * sizeof(uint8_t));
    memcpy(&flow_key_byte[1], &i_hdr->dst.u_addr.ip4.addr, 4 * sizeof(uint8_t));
    memcpy(&flow_key_byte[5], &i_hdr->src.u_addr.ip4.addr, 4 * sizeof(uint8_t));
    memcpy(&flow_key_byte[9], &i_hdr->dst_p, 2 * sizeof(uint8_t));
    memcpy(&flow_key_byte[11], &i_hdr->src_p, 2 * sizeof(uint8_t));

    /* Convert to string */
    char flow_key[27];
    for (int i = 0; i < 13; i++) {
        sprintf(&flow_key[i*2], "%02x", flow_key_byte[i]);
    }
    flow_key[26] = '\0';
    ZITI_LOG(DEBUG, "flow key is %s\n", flow_key);

    /* Check if key exists, no need for new entry or outbound handle */
    struct geneve_flow_s *flow_info = model_map_get(&geneve->flow_ids, flow_key);
    if (flow_info == NULL) {

        if ((i_hdr->proto_type == IPPROTO_TCP) && !(i_hdr->flags & TCP_SYN)) {
            ZITI_LOG(DEBUG, "This is not a syn packet, the tcp flow %s is not active.\n", flow_key);
            return;
        }
        /* Initialize flow struct */
        flow_info = calloc(1, sizeof(struct geneve_flow_s));

        /* Fill in values for flow struct */;
        flow_info->send_address = *(struct sockaddr_in *) addr;
        flow_info->send_address.sin_port = lwip_htons(GENEVE_UDP_PORT);
        flow_info->bind_address = *(struct sockaddr_in *) addr;
        inet_aton(IP_LOCAL_BIND, &flow_info->bind_address.sin_addr);
        memcpy(&flow_info->id[0], &buf->base[0], 40 * sizeof(uint8_t));

        /* Copy Geneve header info into flow_ids map */
        model_map_set(&geneve->flow_ids, flow_key, flow_info);

        size_t map_size = model_map_size(&geneve->flow_ids);
        ZITI_LOG(DEBUG, "flow map size when adding new key is %zu\n", map_size);

        ZITI_LOG(DEBUG, "Geneve (2) Send Address %s:%d\n", inet_ntoa(flow_info->send_address.sin_addr), htons ( flow_info->send_address.sin_port));
        ZITI_LOG(DEBUG, "Geneve (2) Bind Address %s:%d\n", inet_ntoa(flow_info->bind_address.sin_addr), htons ( flow_info->bind_address.sin_port));

        /* Initialize outbound handle */
        if (uv_udp_init(geneve->loop, &flow_info->udp_handle_out)) {
            ZITI_LOG(ERROR, "Failed to initialize uv UDP handle out for geneve\n");
        }
        if (uv_udp_bind(&flow_info->udp_handle_out, (const struct sockaddr *) &flow_info->bind_address,
                        UV_UDP_REUSEADDR)) {
            ZITI_LOG(ERROR, "Could not add netlink socket to uv UDP handle out for geneve");
        }
    } else {
        if (i_hdr->flags & (TCP_FIN | TCP_RST)) {
            /* this is  a FIN/FIN ACK/FIN ACK PSH/RST segment, set  flow_done_in to true for closure */
            flow_info->flow_done_in = true;
            //flow_info->conn_timer = calloc(1, sizeof(uv_timer_t));
            //flow_info->conn_timer->data = flow_info;
            //uv_timer_init(geneve->loop, flow_info->conn_timer);
        }
        if (flow_info->flow_done_out && flow_info->flow_done_in) {
            uv_close((uv_handle_t *) &flow_info->udp_handle_out, NULL);
            model_map_remove(&geneve->flow_ids, flow_key);
            size_t map_size = model_map_size(&geneve->flow_ids);
            ZITI_LOG(DEBUG, "flow map size deleted by 1 ans is at %zu\n", map_size);
        }
    }

    /* Let lwip process the packet */
    on_packet(buf->base + 40, nread - 40, netif_default);
    free(buf->base);
    free(i_hdr);
}

ssize_t geneve_write(netif_handle geneve, const void *buf, size_t len) {

    /* read flow map  with received key to get flow details to build the geneve header */
    u8_t received_flow_key_byte[13];
    memcpy(&received_flow_key_byte[0], &buf[9], 1*sizeof(uint8_t));
    memcpy(&received_flow_key_byte[1], &buf[12], 12*sizeof(uint8_t));

    /* Convert to string */
    struct geneve_packet *g_pkt = calloc(1, sizeof(struct geneve_packet));
    for (int i = 0; i < 13; i++) {
        sprintf(&g_pkt->received_flow_key[i*2], "%02x", received_flow_key_byte[i]);
    }
    g_pkt->received_flow_key[26] = '\0';
    ZITI_LOG(DEBUG, "flow key is %s\n", g_pkt->received_flow_key);

    /* Retrieve flow_info based on the received key */
    g_pkt->received_flow = model_map_get(&geneve->flow_ids, g_pkt->received_flow_key);
    if (g_pkt->received_flow != NULL) {
        /* Build the geneve header */
        struct geneve_hdr *g_hdr = calloc(1, sizeof(struct geneve_hdr));
        geneve_overhead_pack(g_hdr, buf, g_pkt->received_flow->id);

        /* Combine 2 buffs into one contiguous geneve packet (header plus ip4 payload) to be sent out */
        g_pkt->buf[0].base = (char*) g_hdr;
        g_pkt->buf[0].len = sizeof(struct geneve_hdr) - 4;
        g_pkt->buf[1].base = malloc(len);
        memcpy(g_pkt->buf[1].base, buf, len);
        g_pkt->buf[1].len = len;

        /* check for fin ack / rst to close handle out and delete map entry for that session */
        struct inner_ip_hdr_info *i_hdr = calloc(1, sizeof(struct inner_ip_hdr_info));
        parse_ipheader(i_hdr, buf);
        if (i_hdr != NULL) {
            ZITI_LOG(DEBUG, "flag in header is %X\n", i_hdr->flags);
            if (i_hdr->flags & (TCP_FIN | TCP_RST)) {
                /* this is  a FIN/RST segment, close the current session */
                g_pkt->received_flow->flow_done_out = true;
            }
        }
        free(i_hdr);
        size_t map_size = model_map_size(&geneve->flow_ids);
        ZITI_LOG(DEBUG, "flow map size is %zu\n", map_size);

        /* Initializing req to use in the call back funtion */
        uv_udp_send_t *send_req = malloc(sizeof(uv_udp_send_t));
        send_req->data = g_pkt;

        /* Send the geneve packet out */
        ZITI_LOG(DEBUG, "Geneve (2) Send Address %s:%d\n", inet_ntoa( g_pkt->received_flow->send_address.sin_addr), htons ( g_pkt->received_flow->send_address.sin_port));
        ZITI_LOG(DEBUG, "Geneve (2) Bind Address %s:%d\n", inet_ntoa( g_pkt->received_flow->bind_address.sin_addr), htons ( g_pkt->received_flow->bind_address.sin_port));
        uv_udp_send(send_req, &g_pkt->received_flow->udp_handle_out, g_pkt->buf, 2, (const struct sockaddr*) &g_pkt->received_flow->send_address, write_status_cb);
        if (g_pkt->received_flow->flow_done_out && g_pkt->received_flow->flow_done_in) {
            uv_close((uv_handle_t *) &g_pkt->received_flow->udp_handle_out, NULL);
            model_map_remove(&geneve->flow_ids, g_pkt->received_flow_key);
            map_size = model_map_size(&geneve->flow_ids);
            ZITI_LOG(DEBUG, "flow map size deleted by 1 ans is at %zu\n", map_size);
        }
    } else {
        ZITI_LOG(ERROR, "flow key %s does not exist \n", g_pkt->received_flow_key);
        free(g_pkt);
    }
}

netif_driver geneve_open(uv_loop_t *loop, char *error, size_t error_len) {

    struct netif_handle_s *geneve = calloc(1, sizeof(struct netif_handle_s));
    geneve->loop = loop;
    struct sockaddr_in geneve_addr;
    //const char *ip_bind = "0.0.0.0";
    /* retrieve ip and port from sockaddr_in */
    uv_ip4_addr(IP_LOCAL_BIND, GENEVE_UDP_PORT, &geneve_addr);
    fprintf(stderr, "Geneve Port open %s:%d\n", inet_ntoa(geneve_addr.sin_addr), htons (geneve_addr.sin_port));
    /* Add geneve socket to event loop */
    if (uv_udp_init(geneve->loop, &geneve->udp_handle_in)) {
        snprintf(error, error_len, "Failed to initialize uv UDP handle in for geneve\n");
        return NULL;
    }
    // Initialized memory for the driver struct
    struct netif_driver_s *driver = calloc(1, sizeof(struct netif_driver_s));

    if (uv_udp_bind(&geneve->udp_handle_in, (const struct sockaddr *) &geneve_addr, UV_UDP_REUSEADDR)) {
        snprintf(error, error_len, "Could not add netlink socket to uv geneve\n");
        return NULL;
    }
    /* udp handle to pass pointer to on_packet */
    geneve->udp_handle_in.data = driver;

    if (uv_udp_recv_start(&geneve->udp_handle_in, read_alloc_cb, geneve_udp_read)) {
        snprintf(error, error_len, "Could not start receiving netlink packets for geneve\n");
        return NULL;
    }

    driver->handle = geneve;
    driver->write = geneve_write;
    driver->close = geneve_close;

    return driver;
}