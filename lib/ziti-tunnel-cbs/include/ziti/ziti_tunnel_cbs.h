#ifndef ZITI_TUNNELER_SDK_ZITI_TUNNEL_CBS_H
#define ZITI_TUNNELER_SDK_ZITI_TUNNEL_CBS_H

#include "ziti/ziti_tunnel.h"
#include "ziti/ziti.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TUNNELER_APP_DATA_MODEL(XX, ...) \
XX(dst_protocol, string, none, dst_protocol, __VA_ARGS__)\
XX(dst_hostname, string, none, dst_hostname, __VA_ARGS__)\
XX(dst_ip, string, none, dst_ip, __VA_ARGS__)\
XX(dst_port, string, none, dst_port, __VA_ARGS__)\
XX(src_protocol, string, none, src_protocol, __VA_ARGS__)\
XX(src_ip, string, none, src_ip, __VA_ARGS__)\
XX(src_port, string, none, src_port, __VA_ARGS__)\
XX(source_addr, string, none, source_addr, __VA_ARGS__)

DECLARE_MODEL(tunneler_app_data, TUNNELER_APP_DATA_MODEL)

#define TUNNEL_COMMANDS(XX,...) \
XX(ZitiDump, __VA_ARGS__)    \
XX(LoadIdentity, __VA_ARGS__)   \
XX(ListIdentities, __VA_ARGS__) \
XX(DisableIdentity, __VA_ARGS__) \
XX(EnableMFA, __VA_ARGS__)  \
XX(SubmitMFA, __VA_ARGS__)  \
XX(VerifyMFA, __VA_ARGS__)  \
XX(RemoveMFA, __VA_ARGS__)  \
XX(GenerateMFACodes, __VA_ARGS__) \
XX(GetMFACodes, __VA_ARGS__)

DECLARE_ENUM(TunnelCommand, TUNNEL_COMMANDS)

#define TUNNEL_CMD(XX, ...) \
XX(command, TunnelCommand, none, command, __VA_ARGS__) \
XX(data, json, none, data, __VA_ARGS__)

#define TUNNEL_CMD_RES(XX, ...) \
XX(success, bool, none, success, __VA_ARGS__) \
XX(error, string, none, error, __VA_ARGS__)\
XX(data, json, none, data, __VA_ARGS__)

#define TNL_LOAD_IDENTITY(XX, ...) \
XX(identifier, string, none, identifier, __VA_ARGS__)\
XX(path, string, none, path, __VA_ARGS__)

#define TNL_DISABLE_IDENTITY(XX, ...) \
XX(path, string, none, path, __VA_ARGS__)

#define TNL_IDENTITY_INFO(XX, ...) \
XX(name, string, none, name, __VA_ARGS__) \
XX(config, string, none, config, __VA_ARGS__) \
XX(network, string, none, network, __VA_ARGS__) \
XX(id, string, none, id, __VA_ARGS__)

#define TNL_IDENTITY_LIST(XX, ...) \
XX(identities, tunnel_identity_info, array, identities, __VA_ARGS__)

#define TNL_ZITI_DUMP(XX, ...) \
XX(identifier, string, none, id, __VA_ARGS__) \
XX(dump_path, string, none, dump_path, __VA_ARGS__)

#define TNL_ENABLE_MFA(XX, ...) \
XX(identifier, string, none, id, __VA_ARGS__)

#define TNL_MFA_ENROL_RES(XX,...) \
XX(identifier, string, none, identifier, __VA_ARGS__) \
XX(is_verified, bool, none, is_verified, __VA_ARGS__) \
XX(provisioning_url, string, none, provisioning_url, __VA_ARGS__) \
XX(recovery_codes, string, array, recovery_codes, __VA_ARGS__)

// MFA auth command
#define TNL_SUBMIT_MFA(XX, ...) \
XX(identifier, string, none, identifier, __VA_ARGS__) \
XX(code, string, none, code, __VA_ARGS__)

// MFA auth command
#define TNL_VERIFY_MFA(XX, ...) \
XX(identifier, string, none, identifier, __VA_ARGS__) \
XX(code, string, none, code, __VA_ARGS__)

#define TNL_REMOVE_MFA(XX, ...) \
XX(identifier, string, none, id, __VA_ARGS__) \
XX(code, string, none, code, __VA_ARGS__)

#define TNL_GENERATE_MFA_CODES(XX, ...) \
XX(identifier, string, none, id, __VA_ARGS__) \
XX(code, string, none, code, __VA_ARGS__)

#define TNL_MFA_RECOVERY_CODES(XX, ...) \
XX(identifier, string, none, id, __VA_ARGS__) \
XX(recovery_codes, string, array, recovery_codes, __VA_ARGS__)

#define TNL_GET_MFA_CODES(XX, ...) \
XX(identifier, string, none, id, __VA_ARGS__) \
XX(code, string, none, code, __VA_ARGS__)

DECLARE_MODEL(tunnel_comand, TUNNEL_CMD)
DECLARE_MODEL(tunnel_result, TUNNEL_CMD_RES)
DECLARE_MODEL(tunnel_load_identity, TNL_LOAD_IDENTITY)
DECLARE_MODEL(tunnel_identity_info, TNL_IDENTITY_INFO)
DECLARE_MODEL(tunnel_identity_list, TNL_IDENTITY_LIST)
DECLARE_MODEL(tunnel_ziti_dump, TNL_ZITI_DUMP)
DECLARE_MODEL(tunnel_disable_identity, TNL_DISABLE_IDENTITY)
DECLARE_MODEL(tunnel_enable_mfa, TNL_ENABLE_MFA)
DECLARE_MODEL(tunnel_mfa_enrol_res, TNL_MFA_ENROL_RES)
DECLARE_MODEL(tunnel_submit_mfa, TNL_SUBMIT_MFA)
DECLARE_MODEL(tunnel_verify_mfa, TNL_VERIFY_MFA)
DECLARE_MODEL(tunnel_remove_mfa, TNL_REMOVE_MFA)
DECLARE_MODEL(tunnel_generate_mfa_codes, TNL_GENERATE_MFA_CODES)
DECLARE_MODEL(tunnel_mfa_recovery_codes, TNL_MFA_RECOVERY_CODES)
DECLARE_MODEL(tunnel_get_mfa_codes, TNL_GET_MFA_CODES)

#define TUNNEL_EVENTS(XX, ...) \
XX(ContextEvent, __VA_ARGS__) \
XX(ServiceEvent, __VA_ARGS__)  \
XX(MFAEvent, __VA_ARGS__)

DECLARE_ENUM(TunnelEvent, TUNNEL_EVENTS)

#define BASE_EVENT_MODEL(XX, ...) \
XX(identifier, string, none, identifier, __VA_ARGS__) \
XX(event_type, TunnelEvent, none, type, __VA_ARGS__)

#define ZTX_EVENT_MODEL(XX, ...)  \
BASE_EVENT_MODEL(XX, __VA_ARGS__)            \
XX(status, string, none, status, __VA_ARGS__)

#define MFA_EVENT_MODEL(XX, ...)  \
BASE_EVENT_MODEL(XX, __VA_ARGS__)               \
XX(provider, string, none, provider, __VA_ARGS__)

DECLARE_MODEL(base_event, BASE_EVENT_MODEL)
DECLARE_MODEL(ziti_ctx_event, ZTX_EVENT_MODEL)
DECLARE_MODEL(mfa_event, MFA_EVENT_MODEL)

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

    // count of ziti_write requests yet to be ack'ed by ziti sdk
    size_t in_wreqs;
};

typedef void (*event_cb)(const base_event* event);
typedef void (*command_cb)(const tunnel_result *, void *ctx);
typedef struct {
    int (*process)(const tunnel_comand *cmd, command_cb cb, void *ctx);
    int (*load_identity)(const char *identifier, const char *path, command_cb, void *ctx);
    // do not use, temporary accessor
    ziti_context (*get_ziti)(const char *identifier);
} ziti_tunnel_ctrl;

/**
  * replaces first occurrence of _substring_ in _source_ with _with_.
  * returns pointer to last replaced char in _source_, or NULL if no replacement was made.
  */
char *string_replace(char *source, size_t sourceSize, const char *substring, const char *with);

/** called by tunneler SDK after a client connection is intercepted */
void *ziti_sdk_c_dial(const void *app_intercept_ctx, struct io_ctx_s *io);

/** called from tunneler SDK when intercepted client sends data */
ssize_t ziti_sdk_c_write(const void *ziti_io_ctx, void *write_ctx, const void *data, size_t len);

/** called by tunneler SDK after a client connection's RX is closed
 * return 0 if TX should still be open, 1 if both sides are closed */
int ziti_sdk_c_close(void *io_ctx);
int ziti_sdk_c_close_write(void *io_ctx);

host_ctx_t *ziti_sdk_c_host(void *ziti_ctx, uv_loop_t *loop, const char *service_name, cfg_type_e cfgtype, const void *cfg);

/** passed to ziti-sdk via ziti_options.service_cb */
tunneled_service_t *ziti_sdk_c_on_service(ziti_context ziti_ctx, ziti_service *service, int status, void *tnlr_ctx);

void remove_intercepts(ziti_context ziti_ctx, void *tnlr_ctx);

const ziti_tunnel_ctrl* ziti_tunnel_init_cmd(uv_loop_t *loop, tunneler_context, event_cb);


#ifdef __cplusplus
}
#endif

#endif //ZITI_TUNNELER_SDK_ZITI_TUNNEL_CBS_H