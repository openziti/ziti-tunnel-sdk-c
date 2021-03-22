#include <string.h>
#include <stdio.h>

#include "ziti_tunnel_priv.h"

/** return the intercept context for a packet based on its destination ip:port */
intercept_ctx_t *lookup_intercept_by_address(tunneler_context tnlr_ctx, const char *protocol, ip_addr_t *dst_addr, int dst_port_low, int dst_port_high) {
    struct intercept_ctx_s *intercept;

    if (tnlr_ctx == NULL) {
        TNL_LOG(DEBUG, "null tnlr_ctx");
        return NULL;
    }

    STAILQ_FOREACH(intercept, &tnlr_ctx->intercepts, entries) {
        protocol_t *p;
        bool protocol_match = false;
        bool address_match = false;

        STAILQ_FOREACH(p, &intercept->protocols, entries) {
            if (strcmp(p->protocol, protocol) == 0) {
                protocol_match = true;
                break;
            }
        }
        if (!protocol_match) continue;

        address_t *c;
        STAILQ_FOREACH(c, &intercept->addresses, entries) {
            if (IP_IS_V4(&c->ip) && c->prefix_len != 32) {
                if (ip_addr_netcmp(dst_addr, &c->ip, ip_2_ip4(&c->_netmask))) {
                    address_match = true;
                    break;
                }
            } else if (IP_IS_V6(&c->ip) && c->prefix_len != 128) {
                TNL_LOG(ERR, "IPv6 CIDR intercept is not currently supported");
            } else if (ip_addr_cmp(&c->ip, dst_addr)) {
                address_match = true;
                break;
            }
        }
        if (!address_match) continue;

        port_range_t *pr;
        STAILQ_FOREACH(pr, &intercept->port_ranges, entries) {
            if (dst_port_low >= pr->low && dst_port_high <= pr->high) {
                return intercept;
            }
        }
    }

    return NULL;
}