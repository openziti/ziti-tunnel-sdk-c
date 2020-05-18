#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "ziti/ziti_log.h"
#include "intercept.h"
#include "ziti_tunneler_priv.h"

extern int add_v1_intercept(tunneler_context tnlr_ctx, const void *ziti_ctx, const char *service_name, const char *hostname, int port) {
    if (tnlr_ctx == NULL) {
        ZITI_LOG(ERROR, "null tnlr_ctx");
        return -1;
    }
    struct intercept_s *new, *last;

    for (last = tnlr_ctx->intercepts; last != NULL; last = last->next) {
        if (last->next == NULL) break;
    }

    new = calloc(1, sizeof(struct intercept_s));
    new->ctx.service_name = strdup(service_name);
    new->ctx.ziti_ctx = ziti_ctx;
    new->next = NULL;
    new->cfg_version = 1;
    new->cfg.v1.hostname = strdup(hostname);
    if (ipaddr_aton(hostname, &new->cfg.v1.resolved_hostname) == 0) {
        /* TODO generate IP address when service cfg uses hostname. */
        ZITI_LOG(ERROR, "sorry! support for DNS hostnames is coming soon");
        free((char *)new->ctx.service_name);
        free(new->cfg.v1.hostname);
        free(new);
        return -1;
    }
    new->cfg.v1.port = port;

    if (last == NULL) {
        tnlr_ctx->intercepts = new;
    } else {
        last->next = new;
    }

    return 0;
}

void remove_intercept(tunneler_context tnlr_ctx, const char *service_name) {
    struct intercept_s *intercept, *prev = NULL;

    if (tnlr_ctx == NULL) {
        ZITI_LOG(DEBUG, "null tnlr_ctx");
        return;
    }

    for (intercept = tnlr_ctx->intercepts; intercept != NULL; intercept = intercept->next) {
        if (strcmp(intercept->ctx.service_name, service_name) == 0) {
            if (prev != NULL) {
                prev->next = intercept->next;
            } else {
                tnlr_ctx->intercepts = intercept->next;
            }
            // TODO close active connections
            free((char *)intercept->ctx.service_name);
            switch (intercept->cfg_version) {
                case 1:
                    free(intercept->cfg.v1.hostname);
                    break;
            }
        }
        prev = intercept;
    }
}

/** return the intercept context for a packet based on its destination ip:port */
intercept_ctx_t *lookup_l4_intercept(tunneler_context tnlr_ctx, ip_addr_t *dst_addr, int dst_port) {
    struct intercept_s *intercept;

    if (tnlr_ctx == NULL) {
        ZITI_LOG(DEBUG, "null tnlr_ctx");
        return NULL;
    }

    for (intercept = tnlr_ctx->intercepts; intercept != NULL; intercept = intercept->next) {
        if (intercept->cfg_version == 1) {
            if (ip_addr_cmp(&intercept->cfg.v1.resolved_hostname, dst_addr) &&
                intercept->cfg.v1.port == dst_port) {
                return &intercept->ctx;
            }
        }
    }

    return NULL;
}