#ifndef ZITI_TUNNELER_SDK_TUN_H
#define ZITI_TUNNELER_SDK_TUN_H

//#include <linux/if.h>
#include <net/if.h>
#include "ziti/netif_driver.h"

struct netif_handle_s {
    int  fd;
    char name[IFNAMSIZ];
};

extern netif_driver tun_open(uint32_t tun_ip, uint32_t dns_ip, const char *cidr, char *error, size_t error_len);

#endif //ZITI_TUNNELER_SDK_TUN_H
