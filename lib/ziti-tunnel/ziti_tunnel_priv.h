#ifndef ZITI_TUNNELER_SDK_ZITI_TUNNELER_PRIV_H
#define ZITI_TUNNELER_SDK_ZITI_TUNNELER_PRIV_H

#include "ziti/ziti_tunnel.h"
#include "lwip/netif.h"

#include <ziti/ziti_tunnel.h>

/* xxx.xxx.xxx.xxx/xx */
#define MAX_ROUTE_LEN (4*4 + 2 + 1)

enum {
    NONE,
    ERR,
    WARN,
    INFO,
    DEBUG,
    VERBOSE,
    TRACE
};

#define TNL_LOG(level, fmt, ...) do { \
if (tunnel_logger && level <= tunnel_log_level) { tunnel_logger(level, __FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__); }\
} while(0)

extern int tunnel_log_level;
typedef void (*tunnel_logger_f)(int level, const char *file, unsigned int line, const char *func, const char *fmt, ...);
extern tunnel_logger_f tunnel_logger;

struct intercept_ctx_s {
    tunneler_context tnlr_ctx;
    char *service_name;
    void *app_intercept_ctx;

    protocol_list_t protocols;
    address_list_t addresses;
    port_range_list_t port_ranges;

    STAILQ_ENTRY(intercept_ctx_s) entries;
};

struct excluded_route_s {
    char route[MAX_ROUTE_LEN];
    LIST_ENTRY(excluded_route_s) _next;
};

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
    LIST_HEAD(exclusions, excluded_route_s) excluded_rts;

    dns_manager *dns;
    struct udp_pcb *dns_pcb;
} *tunneler_context;

/** return the intercept context for a packet based on its destination ip:port */
extern intercept_ctx_t *lookup_intercept_by_address(tunneler_context tnlr_ctx, const char *protocol, ip_addr_t *dst_addr, int dst_port);

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
    uv_timer_t *conn_timer;
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

extern int delete_route(netif_driver tun, address_t *dest);

#endif //ZITI_TUNNELER_SDK_ZITI_TUNNELER_PRIV_H
