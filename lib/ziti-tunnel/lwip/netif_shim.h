// heavily inspired by https://github.com/FlowerWrong/ip2socks/blob/master/src/netif/tunif.h
//
// another example lwip tunif https://github.com/russdill/lwip/tree/tap-via-socks

#ifndef ZITI_TUNNELER_SDK_NETIF_SHIM_H
#define ZITI_TUNNELER_SDK_NETIF_SHIM_H

#ifdef __cplusplus
extern "C" {
#endif

#include "lwip/netif.h"

err_t netif_shim_init(struct netif *netif);

void netif_shim_input(struct netif *netif);

void on_packet(const char *buf, ssize_t nr, void *netif);

#ifdef __cplusplus
}
#endif

#endif //ZITI_TUNNELER_SDK_NETIF_SHIM_H