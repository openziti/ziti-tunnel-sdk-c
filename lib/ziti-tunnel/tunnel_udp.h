/*
 Copyright NetFoundry Inc.

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
extern tunneler_io_context new_udp_tunneler_io_context(tunneler_context tnlr_ctx, io_ctx_t *io, const char *service_name, const char *src, const char *dst, struct udp_pcb *pcb);
extern void tunneler_udp_dial_completed(struct io_ctx_s *io, bool ok);
extern u8_t recv_udp(void *tnlr_ctx_arg, struct raw_pcb *pcb, struct pbuf *p, const ip_addr_t *addr);
extern void on_udp_client_data(void *io_context, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port);
extern void tunneler_udp_ack(struct write_ctx_s *write_ctx);
extern int tunneler_udp_close(struct udp_pcb *pcb);
/** return list of io contexts for active connections to the given service. caller must free the returned pointer */
extern struct io_ctx_list_s *tunneler_udp_active(const void *zi_ctx);

extern void tunneler_udp_get_conn(tunnel_ip_conn *conn, struct udp_pcb *pcb);

#endif //ZITI_TUNNELER_SDK_TUNNELER_UDP_H
