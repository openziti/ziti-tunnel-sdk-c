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

#endif //ZITI_TUNNELER_SDK_ZITI_TUNNELER_PRIV_H
