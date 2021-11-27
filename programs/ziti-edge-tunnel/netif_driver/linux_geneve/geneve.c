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
#define BUFFER_SIZE 64 * 1024

static int geneve_close(netif_handle geneve) {
    uv_udp_recv_stop(&geneve->udp_handle_in);
    uv_close((uv_handle_t *) geneve, NULL);
}

static void my_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    buf->base = malloc(BUFFER_SIZE);
    buf->len = BUFFER_SIZE;
    // TODO throttle to limit the memory usage
}

static struct geneve_hdr geneve_overhead_pack(const void *buf) {

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

    /* Initialize IP variables */
    ip_addr_t src, dst;
    u16_t iphdr_hlen, src_p, dst_p;
    char proto_type;
    char ip_version = IPH_V((struct ip_hdr *)(buf->base + AWS_GNV_HDR_LEN));

    /* filter IP header to get inner IP addresses */
    switch (ip_version) {
        case 4: {
            struct ip_hdr *iphdr = (struct ip_hdr*) (buf->base + AWS_GNV_HDR_LEN);
            iphdr_hlen = IPH_HL_BYTES(iphdr);
            proto_type = IPH_PROTO(iphdr);
            ip_addr_copy_from_ip4(src, iphdr->src);
            ip_addr_copy_from_ip4(dst, iphdr->dest);
        }
            break;
        case 6: {
            struct ip6_hdr *iphdr = (struct ip6_hdr*) (buf->base + AWS_GNV_HDR_LEN);
            iphdr_hlen = IP6_HLEN;
            proto_type = IP6H_NEXTH(iphdr);
            ip_addr_copy_from_ip6_packed(src, iphdr->src);
            ip_addr_copy_from_ip6_packed(dst, iphdr->dest);
        }
            break;
        default:
            ZITI_LOG(INFO, "unsupported IP protocol version: %d", ip_version);
            return;
    }

    /* filter TCP/UDP header to get ports */
    switch (proto_type) {
        case 6: {
            struct tcp_hdr *tcphdr = (struct tcp_hdr *)(buf->base + AWS_GNV_HDR_LEN + iphdr_hlen);
            src_p = tcphdr->src;
            dst_p = tcphdr->dest;
            flags = TCPH_FLAGS(tcphdr);
            if (!(flags & TCP_SYN)) {
                /* this isn't a SYN segment, so let lwip process it */
                return;
            }
        }
            break;
        case 17: {
            struct udp_hdr *udphdr = (struct udp_hdr *)(buf->base + AWS_GNV_HDR_LEN + iphdr_hlen);
            src_p = udphdr->src;
            dst_p = udphdr->dest;
        }
            break;
        default:
            ZITI_LOG(INFO, "unsupported protocol type: %d", proto_type);
            return;
    }

    /* Log the connection details in debug mode */
    if (proto_type == 6) {
        ZITI_LOG(DEBUG, "received TCP datagram %s:%d->%s:%d",
                 ipaddr_ntoa(&src), ntohs(src_p),
                 ipaddr_ntoa(&dst), ntohs(dst_p));
    }
    if (proto_type == 17) {
        ZITI_LOG(DEBUG, "received UDP datagram %s:%d->%s:%d",
                 ipaddr_ntoa(&src), ntohs(src_p),
                 ipaddr_ntoa(&dst), ntohs(dst_p));
    }

    /*
       build flow key with the order expected in return packet i.e.:
       [0:3]    Return Source Ip        <- Received Destination Ip
       [4:7]    Return Destination Ip   <- Received Source Ip
       [8:9]    Return Source Port      <- Received Destination Port
       [10:11]  Return Destination Port <- Received Source Port
     */
    uint8_t *flow_key = malloc(12*sizeof(uint8_t));
    memcpy(&flow_key[0], &dst.u_addr.ip4.addr, 4*sizeof(uint8_t));
    memcpy(&flow_key[4], &src.u_addr.ip4.addr, 4*sizeof(uint8_t));
    memcpy(&flow_key[8], &dst_p, 2*sizeof(uint8_t));
    memcpy(&flow_key[10], &src_p, 2*sizeof(uint8_t));

    /* Copy Geneve header into flow id */
    geneve->flow_info = calloc(1, sizeof(&geneve->flow_info));
    memcpy(&geneve->flow_info->id[0], &buf->base[0], 40*sizeof(uint8_t));

    /* TODO check if exists with model_map_get */
    model_map_set(&geneve->flow_ids, (char*) flow_key, geneve->flow_info->id);
    size_t map_size = model_map_size(&geneve->flow_ids);

    fprintf(stderr, "flow key is ");
    for (int i=0; i<12; ++i) {
        fprintf(stderr, "%x ", flow_key[i]);
    }
    fprintf(stderr, "\n");

    /* Initialize outbound addresses */;
    geneve->flow_info->send_address = *(struct sockaddr_in*)addr;
    geneve->flow_info->send_address.sin_port = GENEVE_UDP_PORT;
    geneve->flow_info->bind_address = *(struct sockaddr_in*)addr;
    inet_aton(IP_LOCAL_BIND, &geneve->flow_info->bind_address.sin_addr);

    /* Let lwip process the packet */
    on_packet(buf->base + 40, nread - 40, netif_default);
    free(buf->base);
    free(flow_key);
}

ssize_t geneve_write(netif_handle geneve, const void *buf, size_t len) {
    /* TODO encapsulate and read map for packet info */
    uv_udp_send_t send_req;
    uint8_t *received_flow_key = malloc(12*sizeof(uint8_t));
    uint8_t *received_flow_id = malloc(40*sizeof(uint8_t));
    memcpy(&received_flow_key[0], &buf[12], 12*sizeof(uint8_t));
    received_flow_id = model_map_get(&geneve->flow_ids, (char*) received_flow_key);

    fprintf(stderr, "received flow key is ");
    for (int i=0; i<12; ++i) {
        fprintf(stderr, "%x ", received_flow_key[i]);
    }
    fprintf(stderr, "\n");

    fprintf(stderr, "received flow id is ");
    for (int i=0; i<40; ++i) {
        fprintf(stderr, "%x ", received_flow_id[i]);
    }
    fprintf(stderr, "\n");

    /* Creating the geneve header for return packets */
    struct geneve_hdr g_hdr;
    g_hdr.ver = GENEVE_VER;
    g_hdr.oam = 0;
    g_hdr.critical = 0;
    g_hdr.rsvd1 = 0;
    g_hdr.vni[0] = 0;
    g_hdr.vni[1] = 0;
    g_hdr.vni[2] = 0;
    g_hdr.proto_type = lwip_htons(ETH_P_IP);
    g_hdr.rsvd2 = 0;
    g_hdr.options[0].opt_class = htons(0x0108);
    g_hdr.options[0].type = 1;
    g_hdr.options[0].r1 = 0;
    g_hdr.options[0].r2 = 0;
    g_hdr.options[0].r3 = 0;
    memcpy(&g_hdr.options[0].opt_data[0], &received_flow_id[12], 8 * sizeof(uint8_t));
    g_hdr.options[0].length = 2;
    g_hdr.options[1].opt_class = htons(0x0108);
    g_hdr.options[1].type = 2;
    g_hdr.options[1].r1 = 0;
    g_hdr.options[1].r2 = 0;
    g_hdr.options[1].r3 = 0;
    memcpy(&g_hdr.options[1].opt_data[0], &received_flow_id[24], 8 * sizeof(uint8_t));
    g_hdr.options[1].length = 2;
    g_hdr.options[2].opt_class = htons(0x0108);
    g_hdr.options[2].type = 3;
    g_hdr.options[2].r1 = 0;
    g_hdr.options[2].r2 = 0;
    g_hdr.options[2].r3 = 0;
    memcpy(&g_hdr.options[2].opt_data[0], &received_flow_id[36], 4 * sizeof(uint8_t));
    g_hdr.options[2].length = 1;
    g_hdr.opt_len = 32 >> 2;
    /* Combine 2 buffs into one contiguous geneve packet (header plus ip4 payload) */
    uv_buf_t geneve_packet[2] = {
            {
                    .base = (char*) &g_hdr,
                    .len = sizeof(g_hdr) - 4
            },
            {
                    .base = (char*) buf,
                    .len = len
            }
    };
    /* Check if partr of exisitng connection handle */
    /* Initialize outbound handle */
    if (uv_udp_init(geneve->loop, &geneve->flow_info->udp_handle_out)) {
        ZITI_LOG(ERROR, "Failed to initialize uv UDP handle out for geneve\n");
    }
    if (uv_udp_bind(&geneve->flow_info->udp_handle_out, (const struct sockaddr *) &geneve->flow_info->bind_address, UV_UDP_REUSEADDR)) {
        ZITI_LOG(ERROR,"Could not add netlink socket to uv UDP handle out for geneve");
    }

    /* Send the geneve packet out */
    fprintf(stderr, "Geneve (2) Send Address %s:%d\n", inet_ntoa( geneve->flow_info->send_address.sin_addr), htons ( geneve->flow_info->send_address.sin_port));
    uv_udp_send(&send_req, &geneve->flow_info->udp_handle_out, geneve_packet, 2, (const struct sockaddr*) &geneve->flow_info->send_address, NULL);
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

    if (uv_udp_recv_start(&geneve->udp_handle_in, my_alloc_cb, geneve_udp_read)) {
        snprintf(error, error_len, "Could not start receiving netlink packets for geneve\n");
        return NULL;
    }

    driver->handle = geneve;
    driver->write = geneve_write;
    driver->close = geneve_close;

    return driver;
}