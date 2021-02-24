#include <string.h>
#include <stdio.h>

#include "ziti/ziti_log.h"
#include "ziti_tunnel_priv.h"

/** return the intercept context for a packet based on its destination ip:port */
intercept_ctx_t *lookup_intercept_by_address(tunneler_context tnlr_ctx, const char *protocol, ip_addr_t *dst_addr, int dst_port_low, int dst_port_high) {
    struct intercept_ctx_s *intercept;

    if (tnlr_ctx == NULL) {
        ZITI_LOG(DEBUG, "null tnlr_ctx");
        return NULL;
    }

    bool protocol_match = false;
    bool address_match = false;

    STAILQ_FOREACH(intercept, &tnlr_ctx->intercepts, entries) {
        protocol_t *p;
        STAILQ_FOREACH(p, &intercept->protocols, entries) {
            if (strcmp(p->protocol, protocol) == 0) {
                protocol_match = true;
                break;
            }
        }
        if (!protocol_match) continue;

        address_t *c;
        STAILQ_FOREACH(c, &intercept->addresses, entries) {
            // todo CIDR
            if (ip_addr_cmp(&c->ip, dst_addr)) {
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