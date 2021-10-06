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

#ifndef ZITI_TUNNELER_SDK_TUNNELER_UDP_H
#define ZITI_TUNNELER_SDK_TUNNELER_UDP_H

#include <ziti/ziti_tunnel.h>
#include "lwip/udp.h"
#include "lwip/raw.h"

extern ssize_t tunneler_udp_write(struct udp_pcb *pcb, const void *data, size_t len);
extern void tunneler_udp_dial_completed(struct io_ctx_s *io, bool ok);
extern u8_t recv_udp(void *tnlr_ctx_arg, struct raw_pcb *pcb, struct pbuf *p, const ip_addr_t *addr);
extern void tunneler_udp_ack(struct write_ctx_s *write_ctx);
extern int tunneler_udp_close(struct udp_pcb *pcb);
/** return list of io contexts for active connections to the given service. caller must free the returned pointer */
extern struct io_ctx_list_s *tunneler_udp_active(const void *zi_ctx);

#endif //ZITI_TUNNELER_SDK_TUNNELER_UDP_H
