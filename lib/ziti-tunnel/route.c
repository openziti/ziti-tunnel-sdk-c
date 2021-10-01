/*
 Copyright 2021 NetFoundry Inc.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

#include "ziti_tunnel_priv.h"
#include <string.h>

struct route_count {
    char *route;
    int count;
    LIST_ENTRY(route_count) _next;
};

static LIST_HEAD(routes, route_count) route_counts = LIST_HEAD_INITIALIZER(&route_counts);

// macOS ip4: NEIPv4Settings.includedRoutes+=<IP> NEIPv4Settings.subnetMasks+=<IP>
// macOS ip6: NEIPv6Settings.includedRoutes+=<IP> NEIPv6Settings.networkPrefixLengths+=<PREFIX_LEN>
// darwin: route add 1.2.3.4/20 -interface utun0
// linux: ip route add 1.2.3.4/20 dev tun0
// wireguard-windows: mask + IP (https://git.zx2c4.com/wireguard-windows/tree/tunnel/winipcfg/luid.go)
int add_route(netif_driver tun, address_t *dest) {
    //char dest_cidr[128];
    if (tun == NULL) {
        return 1;
    }

    struct route_count *r;
    LIST_FOREACH(r, &route_counts, _next){
        if (strcmp(r->route, dest->str) == 0) break;
    }
    if (r != NULL) {
        r->count += 1;
    } else {
        r = malloc(sizeof(struct route_count));
        r->route = strdup(dest->str);
        r->count = 1;
        LIST_INSERT_HEAD(&route_counts, r, _next);
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
    if (tun == NULL) {
        return 1;
    }

    struct route_count *r;
    LIST_FOREACH(r, &route_counts, _next){
        if (strcmp(r->route, dest->str) == 0) break;
    }
    if (r != NULL) {
        r->count -= 1;
        if (r->count == 0) {
            LIST_REMOVE(r, _next);
            free(r->route);
            free(r);
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