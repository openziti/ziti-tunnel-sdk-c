#ifndef ZITI_TUNNELER_SDK_TUNNELER_TCP_H
#define ZITI_TUNNELER_SDK_TUNNELER_TCP_H

#include <stdbool.h>
#include "nf/ziti_tunneler.h"
#include "lwip/ip_addr.h"
#include "lwip/raw.h"
#include "lwip/priv/tcp_priv.h"

extern int tunneler_tcp_write(struct tcp_pcb *pcb, void *data, size_t len);

extern void tunneler_tcp_dial_completed(struct tcp_pcb *pcb, struct io_ctx_s *io_ctx, bool ok);

extern u8_t recv_tcp(void *tnlr_ctx_arg, struct raw_pcb *pcb, struct pbuf *p, const ip_addr_t *addr);

extern void tunneler_tcp_ack(struct tcp_pcb *pcb, struct pbuf *p);

extern int tunneler_tcp_close(struct tcp_pcb *pcb);

#endif //ZITI_TUNNELER_SDK_TUNNELER_TCP_H
