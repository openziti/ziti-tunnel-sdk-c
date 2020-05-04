#ifndef ZITI_TUNNELER_SDK_TUNNELER_UDP_H
#define ZITI_TUNNELER_SDK_TUNNELER_UDP_H

#include "nf/ziti_tunneler.h"
#include "lwip/udp.h"
#include "lwip/raw.h"

extern ssize_t tunneler_udp_write(struct udp_pcb *pcb, const void *data, size_t len);
extern void tunneler_udp_dial_completed(struct udp_pcb *pcb, struct io_ctx_s *io_ctx, bool ok);
extern u8_t recv_udp(void *tnlr_ctx_arg, struct raw_pcb *pcb, struct pbuf *p, const ip_addr_t *addr);
extern void tunneler_udp_ack(struct udp_pcb *pcb, struct pbuf *p);
extern int tunneler_udp_close(struct udp_pcb *pcb);

#endif //ZITI_TUNNELER_SDK_TUNNELER_UDP_H
