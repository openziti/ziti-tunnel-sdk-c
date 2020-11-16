#ifndef ZITI_TUNNELER_SDK_TUN_H
#define ZITI_TUNNELER_SDK_TUN_H

//#include <linux/if.h>
#include <net/if.h>
#include "ziti/netif_driver.h"

struct netif_handle_s {
    int  fd;
    char name[IFNAMSIZ];
};

extern netif_driver tun_open(char *error, size_t error_len, const char *cidr);
extern void tun_add_route(netif_driver netif, const char *route);

#endif //ZITI_TUNNELER_SDK_TUN_H
