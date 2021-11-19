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

#include <net/if.h>
#include <ziti/netif_driver.h>
#include <ziti/ziti_model.h>
#include <linux/byteorder/little_endian.h>
#include <linux/types.h>

struct geneve_flow_s {
    uint8_t id[18];
    uv_udp_t udp_handle_out;
};

struct netif_handle_s {
    model_map flow_ids;
    uv_udp_t udp_handle_in;
};

extern netif_driver geneve_open(struct uv_loop_s *loop, char *error, size_t error_len);

/*
 * Geneve Overhead structure
 */
#define GENEVE_UDP_PORT	6081
#define GENEVE_VER      0

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
    uint8_t	opt_data[4];
};

struct genevehdr {
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
    struct geneve_opt options[1];
};

#endif //ZITI_TUNNELER_SDK_GENEVE_H
