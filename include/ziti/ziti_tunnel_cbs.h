#ifndef ZITI_TUNNELER_SDK_ZITI_TUNNEL_CBS_H
#define ZITI_TUNNELER_SDK_ZITI_TUNNEL_CBS_H

#include "ziti/ziti_tunnel.h"
#include "ziti/ziti.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TUNNELER_APP_DATA_MODEL(XX, ...) \
XX(data, json, map, data, __VA_ARGS__)

DECLARE_MODEL(tunneler_app_data, TUNNELER_APP_DATA_MODEL)

/** context passed through the tunneler SDK for network i/o */
typedef struct ziti_io_ctx_s {
    ziti_connection      ziti_conn;
    tunneler_io_context  tnlr_io_ctx;
    bool ziti_eof;
    bool tnlr_eof;
} ziti_io_context;

struct hosted_io_ctx_s {
    struct hosted_service_ctx_s *service;
    ziti_connection client;
    union {
        uv_tcp_t tcp;
        uv_udp_t udp;
    } server;
    bool ziti_eof;
    bool tcp_eof;
};

/** called by tunneler SDK after a client connection is intercepted */
void *ziti_sdk_c_dial(const intercept_ctx_t *intercept_ctx, tunneler_io_context tnlr_io_ctx);

/** called from tunneler SDK when intercepted client sends data */
ssize_t ziti_sdk_c_write(const void *ziti_io_ctx, void *write_ctx, const void *data, size_t len);

/** called by tunneler SDK after a client connection's RX is closed
 * return 0 if TX should still be open, 1 if both sides are closed */
int ziti_sdk_c_close(void *io_ctx);

void ziti_sdk_c_host_v1(void *ziti_ctx, uv_loop_t *loop, const char *service_name, const char *proto, const char *hostname, int port);

/** passed to ziti-sdk via ziti_options.service_cb */
void ziti_sdk_c_on_service(ziti_context ziti_ctx, ziti_service *service, int status, void *tnlr_ctx);

#ifdef __cplusplus
}
#endif

#endif //ZITI_TUNNELER_SDK_ZITI_TUNNEL_CBS_H