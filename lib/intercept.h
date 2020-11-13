#ifndef ZITI_TUNNELER_SDK_INTERCEPT_H
#define ZITI_TUNNELER_SDK_INTERCEPT_H

#include "ziti/ziti_tunnel.h"
#include "lwip/ip_addr.h"

struct intercept_s {
    intercept_ctx_t    *ctx;
    struct intercept_s *next;
};

/** return the intercept context for a packet based on its destination ip:port */
extern intercept_ctx_t *lookup_l4_intercept(tunneler_context tnlr_ctx, char *protocol, ip_addr_t *dst_addr, int dst_port);

#endif //ZITI_TUNNELER_SDK_INTERCEPT_H