#ifndef ZITI_TUNNELER_SDK_ZITI_TUNNEL_CBS_H
#define ZITI_TUNNELER_SDK_ZITI_TUNNEL_CBS_H

#include "ziti/ziti_tunnel.h"
#include "ziti/ziti.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TUNNELER_APP_DATA_MODEL(XX, ...) \
XX(data, string, map, data, __VA_ARGS__)

DECLARE_MODEL(tunneler_app_data, TUNNELER_APP_DATA_MODEL)

#define TUNNEL_COMMANDS(XX,...) \
XX(ZitiDump, __VA_ARGS__)    \
XX(LoadIdentity, __VA_ARGS__)   \
XX(ListIdentities, __VA_ARGS__)

DECLARE_ENUM(TunnelCommand, TUNNEL_COMMANDS)

#define TUNNEL_CMD(XX, ...) \
XX(command, TunnelCommand, none, command, __VA_ARGS__) \
XX(data, json, none, data, __VA_ARGS__)

#define TUNNEL_CMD_RES(XX, ...) \
XX(success, bool, none, success, __VA_ARGS__) \
XX(error, string, none, error, __VA_ARGS__)\
XX(data, json, none, data, __VA_ARGS__)

#define LOAD_IDENTITY(XX, ...) \
XX(path, string, none, path, __VA_ARGS__)

#define IDENTITY_INFO(XX, ...) \
XX(name, string, none, name, __VA_ARGS__) \
XX(config, string, none, config, __VA_ARGS__) \
XX(network, string, none, network, __VA_ARGS__) \
XX(id, string, none, id, __VA_ARGS__)

#define IDENTITY_LIST(XX, ...) \
XX(identities, identity_info, array, identities, __VA_ARGS__)

DECLARE_MODEL(tunnel_comand, TUNNEL_CMD)
DECLARE_MODEL(tunnel_result, TUNNEL_CMD_RES)
DECLARE_MODEL(load_identity_cmd, LOAD_IDENTITY)
DECLARE_MODEL(identity_info, IDENTITY_INFO)
DECLARE_MODEL(identity_list, IDENTITY_LIST)

/** context passed through the tunneler SDK for network i/o */
typedef struct ziti_io_ctx_s {
    ziti_connection      ziti_conn;
    bool ziti_eof;
    bool tnlr_eof;
} ziti_io_context;

struct hosted_io_ctx_s {
    struct hosted_service_ctx_s *service;
    ziti_connection client;
    char server_dial_str[64];
    int server_proto_id;
    union {
        uv_tcp_t tcp;
        uv_udp_t udp;
    } server;
    bool ziti_eof;
    bool tcp_eof;
};

typedef void (*command_cb)(const tunnel_result *, void *ctx);
typedef struct {
    int (*process)(const tunnel_comand *cmd, command_cb cb, void *ctx);
    int (*load_identity)(const char *path, command_cb, void *ctx);
} ziti_tunnel_ctrl;

/** called by tunneler SDK after a client connection is intercepted */
void *ziti_sdk_c_dial(const intercept_ctx_t *intercept_ctx, struct io_ctx_s *io);

/** called from tunneler SDK when intercepted client sends data */
ssize_t ziti_sdk_c_write(const void *ziti_io_ctx, void *write_ctx, const void *data, size_t len);

/** called by tunneler SDK after a client connection's RX is closed
 * return 0 if TX should still be open, 1 if both sides are closed */
int ziti_sdk_c_close(void *io_ctx);
int ziti_sdk_c_close_write(void *io_ctx);

host_ctx_t *ziti_sdk_c_host(void *ziti_ctx, uv_loop_t *loop, const char *service_name, cfg_type_e cfgtype, const void *cfg);

/** passed to ziti-sdk via ziti_options.service_cb */
tunneled_service_t *ziti_sdk_c_on_service(ziti_context ziti_ctx, ziti_service *service, int status, void *tnlr_ctx);


const ziti_tunnel_ctrl* ziti_tunnel_init_cmd(uv_loop_t *loop, tunneler_context, command_cb);


#ifdef __cplusplus
}
#endif

#endif //ZITI_TUNNELER_SDK_ZITI_TUNNEL_CBS_H