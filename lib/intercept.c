#include <string.h>
#include <stdio.h>

#include "ziti/ziti_log.h"
#include "intercept.h"
#include "ziti_tunnel_priv.h"

/** return the intercept context for a packet based on its destination ip:port */
intercept_ctx_t *lookup_l4_intercept(tunneler_context tnlr_ctx, char *protocol, ip_addr_t *dst_addr, int dst_port) {
    struct intercept_s *intercept;

    if (tnlr_ctx == NULL) {
        ZITI_LOG(DEBUG, "null tnlr_ctx");
        return NULL;
    }

    bool protocol_match = false;
    bool address_match = false;

    for (intercept = tnlr_ctx->intercepts; intercept != NULL; intercept = intercept->next) {
        protocol_t *p;
        STAILQ_FOREACH(p, &intercept->ctx->protocols, entries) {
            if (strcmp(p->protocol, protocol) == 0) {
                protocol_match = true;
                break;
            }
        }
        if (!protocol_match) continue;

        cidr_t *c;
        STAILQ_FOREACH(c, &intercept->ctx->cidrs, entries) {
            // todo CIDR
            if (ip_addr_cmp(&c->ip, dst_addr)) {
                address_match = true;
                break;
            }
        }
        if (!address_match) continue;

        port_range_t *pr;
        STAILQ_FOREACH(pr, &intercept->ctx->port_ranges, entries) {
            if (dst_port >= pr->low && dst_port <= pr->high) {
                return intercept->ctx;
            }
        }
    }

    return NULL;
}