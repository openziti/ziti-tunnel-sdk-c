#ifndef ZITI_TUNNELER_SDK_INTERCEPT_H
#define ZITI_TUNNELER_SDK_INTERCEPT_H

#include "ziti/ziti_tunneler.h"
#include "lwip/ip_addr.h"

/**
 * service config for ziti-tunneler-client.v1.
 * this intentionally duplicates the intercept structure defined by the ziti-sdk-c model
 * to avoid depending on ziti-sdk-c.
 */
typedef struct intercept_cfg_v1_s {
    char *    hostname;
    ip_addr_t resolved_hostname;
    int       port;
} *intercept_v1_t;

struct intercept_s {
    uint8_t cfg_version;
    struct intercept_ctx_s ctx;
    union {
        struct intercept_cfg_v1_s v1;
    } cfg;
    struct intercept_s *next;
};

extern int add_v1_intercept(tunneler_context tnlr_ctx, const void *ziti_ctx, const char *service_id, const char *service_name, const char *hostname, int port);
extern void remove_intercept(tunneler_context tnlr_ctx, const char *serivce_id);

/** return the intercept context for a packet based on its destination ip:port */
extern intercept_ctx_t *lookup_l4_intercept(tunneler_context tnlr_ctx, ip_addr_t *dst_addr, int dst_port);

#endif //ZITI_TUNNELER_SDK_INTERCEPT_H
