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
    struct intercept_s *intercepts;
    dns_manager *dns;
} *tunneler_context;

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

extern void free_tunneler_io_context(tunneler_io_context *tnlr_io_ctx);

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

#endif //ZITI_TUNNELER_SDK_ZITI_TUNNELER_PRIV_H
