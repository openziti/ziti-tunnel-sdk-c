//
// Created by System Administrator on 4/9/20.
//

#ifndef ZITI_TUNNELER_SDK_LWIPHOOKS_H
#define ZITI_TUNNELER_SDK_LWIPHOOKS_H

#include "lwip/pbuf.h"
#include "netif_shim.h"

extern int ip4_input_hook(struct pbuf *pbuf, struct netif *input_netif);

#endif //ZITI_TUNNELER_SDK_LWIPHOOKS_H
