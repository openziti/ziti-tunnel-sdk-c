#include "ziti_tunnel_priv.h"
#include "ziti/model_support.h"

model_map route_counts = { NULL };

// macOS ip4: NEIPv4Settings.includedRoutes+=<IP> NEIPv4Settings.subnetMasks+=<IP>
// macOS ip6: NEIPv6Settings.includedRoutes+=<IP> NEIPv6Settings.networkPrefixLengths+=<PREFIX_LEN>
// darwin: route add 1.2.3.4/20 -interface utun0
// linux: ip route add 1.2.3.4/20 dev tun0
// wireguard-windows: mask + IP (https://git.zx2c4.com/wireguard-windows/tree/tunnel/winipcfg/luid.go)
int add_route(netif_driver tun, address_t *dest) {
    //char dest_cidr[128];
    if (dest->is_hostname) return 0;
    if (tun == NULL) {
        return 1;
    }

    int *n = model_map_get(&route_counts, dest->str);
    if (n != NULL) {
        *n += 1;
    } else {
        n = malloc(sizeof(int));
        *n = 1;
        model_map_set(&route_counts, dest->str, n);
        return tun->add_route(tun->handle, dest->str);
    }
    return 0;
}

/**
 * delete route only if not in use by actively intercepted service
 * account for subnet routes too.
 */
int delete_route(netif_driver tun, address_t *dest) {
    //char dest_cidr[128];
    if (dest->is_hostname) return 0;
    if (tun == NULL) {
        return 1;
    }

    int *n = model_map_get(&route_counts, dest->str);
    if (n != NULL) {
        *n -= 1;
        if (*n == 0) {
            free(n);
            model_map_remove(&route_counts, dest->str);
            tun->delete_route(tun->handle, dest->str);
        }
    }

    return 0;
}

int prefix_to_ipv4_subnet(int prefix_len, char *subnet, size_t subnet_sz) {
    unsigned long mask = (0xffffffff << (32 - prefix_len)) & 0xffffffff;
    ip_addr_t ip = IPADDR4_INIT(mask);
    snprintf(subnet, subnet_sz, "%s", ipaddr_ntoa(&ip));
    return 0;
}