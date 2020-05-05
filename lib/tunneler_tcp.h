#ifndef ZITI_TUNNELER_SDK_TUNNELER_TCP_H
#define ZITI_TUNNELER_SDK_TUNNELER_TCP_H

#include <stdbool.h>
#include "nf/ziti_tunneler.h"
#include "lwip/ip_addr.h"
#include "lwip/raw.h"
#include "lwip/priv/tcp_priv.h"

extern ssize_t tunneler_tcp_write(struct tcp_pcb *pcb, const void *data, size_t len);

extern void tunneler_tcp_dial_completed(tunneler_io_context *tnlr_io_ctx, void *ziti_io_ctx, bool ok);

extern u8_t recv_tcp(void *tnlr_ctx_arg, struct raw_pcb *pcb, struct pbuf *p, const ip_addr_t *addr);

extern void tunneler_tcp_ack(struct write_ctx_s *write_ctx);

extern int tunneler_tcp_close(struct tcp_pcb *pcb);

#endif //ZITI_TUNNELER_SDK_TUNNELER_TCP_H
