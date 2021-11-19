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

#include "geneve.h"

/* max ipv4 MTU */
#define BUFFER_SIZE 64 * 1024

static int geneve_close(netif_handle geneve) {
    uv_udp_recv_stop(&geneve->udp_handle_in);
    uv_close((uv_handle_t *) geneve, NULL);
}

static void my_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    buf->base = malloc(suggested_size);
    buf->len = suggested_size;
    // TODO throttle to limit the memory usage
}

void geneve_udp_read(uv_udp_t *req, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags) {
    // just log error
    if (nread < 0) {
        ZITI_LOG(ERROR, "Read error %s", uv_err_name(nread));
    }
    // then free buffer and return
    if ( nread <= 0) {
        free(buf->base);
        return;
    }
    // if the length is not equal to 32 bytes
    if ( buf->base[0] != 0x08) {
        ZITI_LOG(ERROR, "Geneve Overhead length error %x", buf->base[0]);
        free(buf->base);
        return;
    }
    // Geneve Peer IP address including port
    struct sockaddr_in* geneve_peer_address = (struct sockaddr_in*)addr;
    /*
      TODO
      catch errors
      Initializing map and driver, handle
     */
    struct geneve_flow_s *flow_info = malloc(sizeof(struct geneve_flow_s));
    uint8_t *flow_key = malloc(12*sizeof(uint8_t));
    netif_driver_t *driver = req->data;
    netif_handle geneve = driver->handle;
    /*
     TODO
       based on fixed Geneve overhead of 40 bytes.
       perhaps more based on Geneve overhead length and key in on the 12 bytes of the first options field
       after the fixed 8 byte initial header fields.
       The key will be reverse of source for easy comparing for the return order bytes. Fill in the flow_key bytes as:
       [0:3]    Return Source Client Address (sourced from Local Destination Client Address Bytes incoming packet)
       [4:7]    Return Destination Client Address (sourced from Local Source Client Address Bytes incoming packet)
       [8:9]    Return Source Client UDP Port (sourced from Local Destination Client Port Bytes incoming packet)
       [10:11]  Return Destination Client UDP Port (sourced from Local Source Client Port Bytes incoming packet)
     */
    memcpy(&flow_key[0], &buf->base[56], 4*sizeof(uint8_t));
    memcpy(&flow_key[4], &buf->base[52], 4*sizeof(uint8_t));
    memcpy(&flow_key[8], &buf->base[62], 2*sizeof(uint8_t));
    memcpy(&flow_key[10], &buf->base[60], 2*sizeof(uint8_t));
    /*
      Fill in the details of the flow_id array plus Geneve Peer IP and Port, Geneve Overhead byte # 12 through 19
      plus bytes copied from sockaddr *addr struct passed into the function
     */
    memcpy(&flow_info->id[0], &buf->base[12], 8*sizeof(uint8_t));
    memcpy(&flow_info->id[8], &buf->base[36], 4*sizeof(uint8_t));
    memcpy(&flow_info->id[12], &geneve_peer_address->sin_addr.s_addr, 4*sizeof(uint8_t));
    memcpy(&flow_info->id[16], &geneve_peer_address->sin_port, 2*sizeof(uint8_t));
    /*
     *TODO check if exists with model_map_get
     */
    model_map_set(&geneve->flow_ids, (char*) flow_key, flow_info->id);
    fprintf(stderr, "\nflow_key: ");for (int i = 0;i < 12;++i) {fprintf(stderr, "%x ", flow_key[i]);}
    fprintf(stderr, "\nflow_id: ");for (int i = 0;i < 14;++i) {fprintf(stderr, "%x ", flow_info->id[i]);}
    fprintf(stderr, "\n");
    size_t map_size = model_map_size(&geneve->flow_ids);
    fprintf(stderr, "flow map size is %d\n", (int)map_size);
    on_packet(buf->base + 40, nread - 40, netif_default);
    free(buf->base);
}

ssize_t geneve_write(netif_handle geneve, const void *buf, size_t len) {
    //TODO encapsulate and read map for packet info
    struct sockaddr_in send_address;
    uv_udp_send_t send_req;
    uint8_t *received_flow_key = malloc(12*sizeof(uint8_t));
    uint8_t *received_flow_id = malloc(18*sizeof(uint8_t));
    memcpy(&received_flow_key[0], &buf[12], 12*sizeof(uint8_t));
    received_flow_id = model_map_get(&geneve->flow_ids, (char*) received_flow_key);
    fprintf(stderr, "\nreceived_key: ");for (int i = 0;i < 12;++i) {fprintf(stderr, "%x ", received_flow_key[i]);}
    fprintf(stderr, "\nreceived_flow_id: ");for (int i = 0;i < 18;++i) {fprintf(stderr, "%x ", received_flow_id[i]);}
    fprintf(stderr, "\n");
    send_address.sin_family = AF_INET;
    uint8_t send_dest_port[] = {0x17, 0xC1};
    memcpy(&send_address.sin_addr.s_addr, &received_flow_id[12], 4*sizeof(uint8_t));
    memcpy(&send_address.sin_port, &send_dest_port[0], 2*sizeof(uint8_t));
    //memcpy(&send_address.sin_port, &received_flow_id[16], 2*sizeof(uint8_t));
    fprintf(stderr, "ipaddress: %s\n", inet_ntoa(send_address.sin_addr));
    fprintf(stderr, "port: %d\n", htons(send_address.sin_port));
    /*
     Creating the geneve header for return packets
     */
    struct genevehdr geneve_header;
    geneve_header.ver = GENEVE_VER;
    geneve_header.oam = 0;
    geneve_header.critical = 0;
    geneve_header.rsvd1 = 0;
    geneve_header.vni[0] = 0;
    geneve_header.vni[1] = 0;
    geneve_header.vni[2] = 0;
    geneve_header.proto_type = lwip_htons(ETH_P_IP);
    geneve_header.rsvd2 = 0;
    geneve_header.options[0].opt_class = htons(0x0108);
    geneve_header.options[0].type = 3;
    geneve_header.options[0].r1 = 0;
    geneve_header.options[0].r2 = 0;
    geneve_header.options[0].r3 = 0;
    memcpy(&geneve_header.options[0].opt_data[0], &received_flow_id[8], 4* sizeof(uint8_t));
    geneve_header.options[0].length = 4 >> 2;
    geneve_header.opt_len = 8 >> 2;
    /*
     Combine 2 buffs into one contiguous geneve packet (header plus ip4 payload)
     */
    uv_buf_t geneve_packet[2] = {
            {
                    .base = (char*) &geneve_header,
                    .len = sizeof(geneve_header)
            },
            {
                    .base = (char*) buf,
                    .len = len
            }
    };
    // Send the geneve packet out

    uv_udp_send(&send_req, &geneve->udp_handle_in, geneve_packet, 2, (const struct sockaddr*) &send_address, NULL);
}

netif_driver geneve_open(uv_loop_t *loop, char *error, size_t error_len) {

    struct netif_handle_s *geneve = calloc(1, sizeof(struct netif_handle_s));
    struct sockaddr_in geneve_addr;
    const char *ip_bind = "0.0.0.0";
    int port_bind = GENEVE_UDP_PORT;
    /* retrieve ip and port from sockaddr_in */
    uv_ip4_addr(ip_bind, port_bind, &geneve_addr);
    fprintf(stderr, "Geneve Port open %s:%d\n", inet_ntoa(geneve_addr.sin_addr), htons (geneve_addr.sin_port));
    /* Add geneve socket to event loop */
    if (uv_udp_init(loop, &geneve->udp_handle_in)) {
        snprintf(error, error_len, "Failed to initialize uv UDP handle for geneve\n");
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