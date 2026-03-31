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

#ifndef ZITI_TUNNELER_SDK_TUNNEL_L2_H
#define ZITI_TUNNELER_SDK_TUNNEL_L2_H

#include <ziti/ziti_tunnel.h>
#include "lwip/pbuf.h"
#include "lwip/netif.h"

extern void tunneler_l2_add_conn(uint16_t ethtype, const io_ctx_t *io);
extern void tunneler_l2_del_conn(uint16_t ethtype);
extern io_ctx_t *tunneler_l2_get_conn(uint16_t ethtype);
extern ssize_t tunneler_l2_write(struct netif *netif, const void *data, size_t len);
extern void tunneler_l2_dial_completed(struct io_ctx_s *io, bool ok);

/** match an incoming l2 frame with a service or existing overlay connection, and dial/forward.
 * returns 1 if the frame was handled (had an intercepted ethtype), or zero. */
extern u8_t recv_l2(struct netif *netif, struct pbuf *p);

extern void tunneler_l2_ack(struct write_ctx_s *write_ctx);
extern int tunneler_l2_close(const char *ethtype);
/** return list of io contexts for active connections to the given service. caller must free the returned pointer */
extern struct io_ctx_list_s *tunneler_l2_active(const void *zi_ctx);

extern void tunneler_udp_get_conn(tunnel_ip_conn *conn, struct udp_pcb *pcb);

#endif //ZITI_TUNNELER_SDK_TUNNEL_L2_H
