#ifndef ZITI_TUNNELER_SDK_ZITI_TUNNELER_PRIV_H
#define ZITI_TUNNELER_SDK_ZITI_TUNNELER_PRIV_H

#include "ziti/ziti_tunnel.h"
#include "lwip/netif.h"

typedef struct tunneler_ctx_s {
    tunneler_sdk_options opts; // this must be first - it is accessed opaquely through tunneler_context*
    struct netif netif;
    struct raw_pcb *tcp;
    struct raw_pcb *udp;
    uv_loop_t      *loop;
    uv_poll_t    netif_poll_req;
    uv_timer_t   lwip_timer_req;
    STAILQ_HEAD(intercept_ctx_list_s, intercept_ctx_s) intercepts;
//    STAILQ_HEAD(hosted_service_ctx_list_s, hosted_service_ctx_s) hosts;
    dns_manager *dns;
} *tunneler_context;

/** return the intercept context for a packet based on its destination ip:port */
extern intercept_ctx_t *lookup_intercept_by_address(tunneler_context tnlr_ctx, const char *protocol, ip_addr_t *dst_addr, int dst_port_low, int dst_port_high);

typedef enum  {
    tun_tcp,
    tun_udp
} tunneler_proto_type;

struct tunneler_io_ctx_s {
    tunneler_context    tnlr_ctx;
    const char *        service_name;
    char                client[64];
    char                intercepted[64];
    tunneler_proto_type proto;
    union {
        struct tcp_pcb *tcp;
        struct {
            struct udp_pcb *pcb;
            struct pbuf *queued;
        } udp;
    };
};

extern void free_tunneler_io_context(tunneler_io_context *tnlr_io_ctx_p);

struct write_ctx_s;

typedef void (*ack_fn)(struct write_ctx_s *write_ctx);

struct write_ctx_s {
    struct pbuf * pbuf;
    union {
        struct tcp_pcb *tcp;
        struct udp_pcb *udp;
    };
    ack_fn ack;
};

const char* assign_ip(const char *hostname);

extern int add_route(netif_driver tun, address_t *dest);

#endif //ZITI_TUNNELER_SDK_ZITI_TUNNELER_PRIV_H
