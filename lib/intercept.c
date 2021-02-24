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
            if (IP_IS_V4(&c->ip) && c->prefix_len != 32) {
                // todo set mask when config is parsed.
                uint8_t bits = 32 - c->prefix_len;
                ip4_addr_t mask;
                ip4_addr_set_u32(&mask, PP_HTONL(0xffffffffUL >> bits << bits));
                if (ip_addr_netcmp(dst_addr, &c->ip, &mask)) {
                    address_match = true;
                    break;
                }
            } else if (IP_IS_V6(&c->ip) && c->prefix_len != 128) {
                ZITI_LOG(ERROR, "IPv6 range intercept not currently supported (%s)", c->str);
                break;
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