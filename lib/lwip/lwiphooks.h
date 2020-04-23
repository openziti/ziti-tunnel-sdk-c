//
// Created by System Administrator on 4/9/20.
//

#ifndef ZITI_TUNNELER_SDK_LWIPHOOKS_H
#define ZITI_TUNNELER_SDK_LWIPHOOKS_H

#include "lwip/pbuf.h"
#include "netif_shim.h"

/* enable the changes in our hook functions to accept all packets. */
#define ZITI_TUNNELER_SDK_TAKE_ALL_PACKETS 1

extern int ip4_input_hook(struct pbuf *pbuf, struct netif *input_netif);

#if LWIP_IPV6
extern int ip6_input_hook(struct pbuf *pbuf, struct netif *input_netif);
#endif

#endif //ZITI_TUNNELER_SDK_LWIPHOOKS_H
