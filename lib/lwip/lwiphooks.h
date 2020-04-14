//
// Created by System Administrator on 4/9/20.
//

#ifndef ZITI_TUNNELER_SDK_LWIPHOOKS_H
#define ZITI_TUNNELER_SDK_LWIPHOOKS_H

#include "lwip/pbuf.h"
#if 0
#include "lwip/tcp.h"
#include "lwip/prot/tcp.h"
#endif
#include "netif_shim.h"

extern int ip4_input_hook(struct pbuf *pbuf, struct netif *input_netif);
#if 0
extern err_t tcp_inpkt_hook(struct tcp_pcb *pcb, struct tcp_hdr *hdr, u16_t optlen, u16_t opt1len, u8_t *opt2, struct pbuf *p);
#endif

#endif //ZITI_TUNNELER_SDK_LWIPHOOKS_H
