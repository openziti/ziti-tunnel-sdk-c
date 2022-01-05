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
#ifndef ZITI_TUNNELER_SDK_GENEVE_H
#define ZITI_TUNNELER_SDK_GENEVE_H

#include <ziti/netif_driver.h>
#include <ziti/ziti_model.h>
#include <linux/types.h>

struct geneve_flow_s {
    u8_t id[40];
    uv_udp_t udp_handle_out;
    /* TODO Convert these to geneneric sockaddr for both ipv4 and ipv6 addresses */
    struct sockaddr_in send_address;
    struct sockaddr_in bind_address;
    uv_timer_t conn_timer;
    uint32_t idle_timeout;
    char search_flow_key[27];
};

struct netif_handle_s {
    model_map flow_list;
    uv_udp_t udp_handle_in;
    struct uv_loop_s *loop;
};

struct inner_ip_hdr_info {
    char proto_type;
    ip_addr_t src;
    ip_addr_t dst;
    u16_t src_p;
    u16_t dst_p;
    u8_t flags;
};

extern netif_driver geneve_open(struct uv_loop_s *loop, char *error, size_t error_len);

/*
 * Geneve Header Struct
 */
#define GENEVE_UDP_PORT         6081
#define GENEVE_VER              0
#define IP_LOCAL_BIND           "0.0.0.0"
#define AWS_GNV_HDR_OPT_LEN     32
#define AWS_GNV_HDR_LEN         40

/* Geneve Header:
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |Ver|  Opt Len  |O|C|    Rsvd.  |          Protocol Type        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |        Virtual Network Identifier (VNI)       |    Reserved   |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                    Variable Length Options                    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Option Header:
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |          Option Class         |      Type     |R|R|R| Length  |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                      Variable Option Data                     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

struct geneve_opt {
    __be16 opt_class;
    uint8_t  type;
#ifdef __LITTLE_ENDIAN
    uint8_t	length:5;
	uint8_t	r3:1;
	uint8_t	r2:1;
	uint8_t	r1:1;
#else
    uint8_t	r1:1;
    uint8_t	r2:1;
    uint8_t	r3:1;
    uint8_t	length:5;
#endif
    uint8_t	opt_data[8];
};

struct geneve_hdr {
#ifdef __LITTLE_ENDIAN
    uint8_t opt_len:6;
	uint8_t ver:2;
	uint8_t rsvd1:6;
	uint8_t critical:1;
	uint8_t oam:1;
#else
    uint8_t ver:2;
    uint8_t opt_len:6;
    uint8_t oam:1;
    uint8_t critical:1;
    uint8_t rsvd1:6;
#endif
    __be16 proto_type;
    uint8_t  vni[3];
    uint8_t  rsvd2;
    struct geneve_opt options[3];
};

#endif //ZITI_TUNNELER_SDK_GENEVE_H
