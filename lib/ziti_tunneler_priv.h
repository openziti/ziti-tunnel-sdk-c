#ifndef ZITI_TUNNELER_SDK_ZITI_TUNNELER_PRIV_H
#define ZITI_TUNNELER_SDK_ZITI_TUNNELER_PRIV_H

#include "lwip/netif.h"

struct tunneler_ctx_s {
    tunneler_sdk_options opts;
    struct netif netif;
    struct raw_pcb *tcp;
    struct raw_pcb *udp;
    uv_poll_t    netif_poll_req;
    uv_timer_t   lwip_timer_req;
    struct intercept_s *intercepts;
};

typedef enum  {
    tun_tcp,
    tun_udp
} tunneler_proto_type;

struct tunneler_io_ctx_s {
    tunneler_context   tnlr_ctx;
    tunneler_proto_type proto;
    union {
        struct tcp_pcb *tcp;
        struct {
            struct udp_pcb *pcb;
            //ziti_udp_cb cb;
            void *ctx;
        } udp;
    };
};

extern void free_tunneler_io_context(tunneler_io_context *tnlr_io_ctx);

struct write_ctx_s {
    struct pbuf * pbuf;
    struct tcp_pcb *pcb;
};

#endif //ZITI_TUNNELER_SDK_ZITI_TUNNELER_PRIV_H
