#include <string.h>
#include <stdio.h>

#include "ziti_tunnel_priv.h"

bool protocol_match(const char *protocol, const protocol_list_t *protocols) {
    protocol_t *p;
    STAILQ_FOREACH(p, protocols, entries) {
        if (strcmp(p->protocol, protocol) == 0) {
            return true;
        }
    }
    return false;
}

bool address_match(const ip_addr_t *addr, const address_list_t *addresses) {
    address_t *a;
    STAILQ_FOREACH(a, addresses, entries) {
        if (IP_IS_V4(&a->ip) && a->prefix_len != 32) {
            if (ip_addr_netcmp(addr, &a->ip, ip_2_ip4(&a->_netmask))) {
                return true;
            }
        } else if (IP_IS_V6(&a->ip) && a->prefix_len != 128) {
            TNL_LOG(ERR, "IPv6 CIDR intercept is not currently supported");
            return false;
        } else if (ip_addr_cmp(&a->ip, addr)) {
            return true;
        }
    }
    return false;
}

bool port_match(int port, const port_range_list_t *port_ranges) {
    port_range_t *pr;
    STAILQ_FOREACH(pr, port_ranges, entries) {
        if (port >= pr->low && port <= pr->high) {
            return true;
        }
    }
    return false;
}

/** return the intercept context for a packet based on its destination ip:port */
intercept_ctx_t *lookup_intercept_by_address(tunneler_context tnlr_ctx, const char *protocol, ip_addr_t *dst_addr, int dst_port) {
    if (tnlr_ctx == NULL) {
        TNL_LOG(DEBUG, "null tnlr_ctx");
        return NULL;
    }

    intercept_ctx_t *intercept;
    LIST_FOREACH(intercept, &tnlr_ctx->intercepts, entries) {
        if (!protocol_match(protocol, &intercept->protocols)) continue;
        if (!address_match(dst_addr, &intercept->addresses)) continue;
        if (port_match(dst_port, &intercept->port_ranges)) {
            return intercept;
        }
    }

    return NULL;
}

void free_intercept(intercept_ctx_t *intercept) {
    while(!STAILQ_EMPTY(&intercept->addresses)) {
        address_t *a = STAILQ_FIRST(&intercept->addresses);
        STAILQ_REMOVE_HEAD(&intercept->addresses, entries);
        free(a);
    }
    while(!STAILQ_EMPTY(&intercept->protocols)) {
        protocol_t *p = STAILQ_FIRST(&intercept->protocols);
        STAILQ_REMOVE_HEAD(&intercept->protocols, entries);
        free(p->protocol);
        free(p);
    }
    while(!STAILQ_EMPTY(&intercept->port_ranges)) {
        port_range_t *pr = STAILQ_FIRST(&intercept->port_ranges);
        STAILQ_REMOVE_HEAD(&intercept->port_ranges, entries);
        free(pr);
    }

    free(intercept->service_name);
    free(intercept);
}