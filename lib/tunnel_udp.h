#ifndef ZITI_TUNNELER_SDK_TUNNELER_UDP_H
#define ZITI_TUNNELER_SDK_TUNNELER_UDP_H

#include "ziti/ziti_tunnel.h"
#include "lwip/udp.h"
#include "lwip/raw.h"

extern ssize_t tunneler_udp_write(struct udp_pcb *pcb, const void *data, size_t len);
extern void tunneler_udp_dial_completed(tunneler_io_context *tnlr_io_ctx, void *ziti_io_ctx, bool ok);
extern u8_t recv_udp(void *tnlr_ctx_arg, struct raw_pcb *pcb, struct pbuf *p, const ip_addr_t *addr);
extern void tunneler_udp_ack(struct write_ctx_s *write_ctx);
extern int tunneler_udp_close(struct udp_pcb *pcb);

#endif //ZITI_TUNNELER_SDK_TUNNELER_UDP_H
