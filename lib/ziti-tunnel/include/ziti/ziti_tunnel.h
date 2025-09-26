/*
 Copyright NetFoundry Inc.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

/**
 * @file ziti_tunneler.h
 * @brief Defines the macros, functions, typedefs and constants required to implement a Ziti
 * tunneler application.
 */

#ifndef ZITI_TUNNELER_SDK_ZITI_TUNNEL_H
#define ZITI_TUNNELER_SDK_ZITI_TUNNEL_H

#include <stdbool.h>
#include "uv.h"
#include "sys/queue.h"
#include "ziti/netif_driver.h"
#include "lwip/ip_addr.h"
#include "ziti/ziti_model.h"

#ifdef __cplusplus
extern "C" {
#endif

#if _WIN32
#define MAXPATHLEN MAX_PATH
#ifndef strcasecmp
#define strcasecmp(a,b) stricmp(a,b)
#endif
#else
#define MAXPATHLEN PATH_MAX
#endif

/** keys used in app_data model map */
extern const char *DST_PROTO_KEY; // "dst_protocol"
extern const char *DST_IP_KEY;    // "dst_ip"
extern const char *DST_PORT_KEY;  // "dst_port"
extern const char *DST_HOST_KEY;  // "dst_hostname"
extern const char *SRC_PROTO_KEY; // "src_protocol"
extern const char *SRC_IP_KEY;    // "src_ip"
extern const char *SRC_PORT_KEY;  // "src_port"
extern const char *SOURCE_IP_KEY; // "source_ip"

typedef struct tunneler_ctx_s *tunneler_context;
typedef struct tunneler_io_ctx_s *tunneler_io_context;
const char * get_intercepted_address(const struct tunneler_io_ctx_s * tnlr_io);
const char * get_client_address(const struct tunneler_io_ctx_s * tnlr_io);
typedef struct hosted_io_ctx_s *hosted_io_context;
typedef struct hosted_service_ctx_s host_ctx_t;
typedef struct io_ctx_s io_ctx_t;

typedef void (*tunnel_logger_f)(int level, const char *module, const char *file, unsigned int line, const char *func, const char *fmt, ...);

typedef enum {
    CLIENT_CFG_V1,    // ziti-tunnel-client.v1
    SERVER_CFG_V1,    // ziti-tunnel-server.v1
    INTERCEPT_CFG_V1, // intercept.v1
    HOST_CFG_V1       // host.v1
} cfg_type_e;

typedef struct protocol_s {
    char *protocol;
    STAILQ_ENTRY(protocol_s) entries;
} protocol_t;
typedef STAILQ_HEAD(protocol_list_s, protocol_s) protocol_list_t;

typedef struct address_s {
    ziti_address za;
    char         str[64];
    STAILQ_ENTRY(address_s) entries;
} address_t;
typedef STAILQ_HEAD(address_list_s, address_s) address_list_t;

typedef struct port_range_s {
    int low;
    int high;
    char str[16]; // [123456-123456]
    STAILQ_ENTRY(port_range_s) entries;
} port_range_t;
typedef STAILQ_HEAD(port_range_list_s, port_range_s) port_range_list_t;

/**
 * called when a client connection is intercepted.
 * implementations are expected to dial the service and return
 * context that will be passed to ziti_read/ziti_write */
typedef void * (*ziti_sdk_dial_cb)(const void *app_intercept_ctx, io_ctx_t *io);
typedef int (*ziti_sdk_close_cb)(void *ziti_io_ctx);
typedef ssize_t (*ziti_sdk_write_cb)(const void *ziti_io_ctx, void *write_ctx, const void *data, size_t len);
typedef host_ctx_t * (*ziti_sdk_host_cb)(void *ziti_ctx, uv_loop_t *loop, const char *service_name, cfg_type_e cfg_type, const void *cfg);

/** data needed to intercept packets and dial the associated ziti service */
typedef struct intercept_ctx_s  intercept_ctx_t;
typedef const ziti_address * (*intercept_match_addr_fn)(ip_addr_t *addr, void *app_intercept_ctx);

extern intercept_ctx_t *intercept_ctx_new(tunneler_context tnlr_ctx, const char *app_id, void *app_intercept_ctx);
extern void intercept_ctx_set_match_addr(intercept_ctx_t *intercept, intercept_match_addr_fn pred);
extern void intercept_ctx_add_protocol(intercept_ctx_t *ctx, const char *protocol);
/** parse address string as hostname|ip|cidr and add result to list of intercepted addresses */
extern void intercept_ctx_add_address(intercept_ctx_t *i_ctx, const ziti_address *address);
extern void intercept_ctx_add_allowed_source_address(intercept_ctx_t *i_ctx, const ziti_address *address);
extern port_range_t *intercept_ctx_add_port_range(intercept_ctx_t *i_ctx, uint16_t low, uint16_t high);
extern void intercept_ctx_override_cbs(intercept_ctx_t *i_ctx, ziti_sdk_dial_cb dial, ziti_sdk_write_cb write, ziti_sdk_close_cb close_write, ziti_sdk_close_cb close);

struct io_ctx_s {
    tunneler_io_context   tnlr_io;
    void *                ziti_io; // context specific to ziti SDK being used by the app.
    const void *          ziti_ctx;
    ziti_sdk_write_cb     write_fn;
    ziti_sdk_close_cb     close_write_fn;
    ziti_sdk_close_cb     close_fn;
};

struct io_ctx_list_entry_s {
    struct io_ctx_s *io;
    SLIST_ENTRY(io_ctx_list_entry_s) entries;
};
SLIST_HEAD(io_ctx_list_s, io_ctx_list_entry_s);




typedef struct tunneler_sdk_options_s {
    netif_driver   netif_driver;
    ziti_sdk_dial_cb    ziti_dial;
    ziti_sdk_close_cb   ziti_close;
    ziti_sdk_close_cb   ziti_close_write;
    ziti_sdk_write_cb   ziti_write;
    ziti_sdk_host_cb    ziti_host;
} tunneler_sdk_options;

extern port_range_t *parse_port_range(uint16_t low, uint16_t high);

/** convert from string */
extern bool ziti_address_from_string(ziti_address *za, const char *hn_or_cidr);
/** convert from internet address types */
extern void ziti_address_from_in_addr(ziti_address *za, const struct in_addr *a);
extern void ziti_address_from_in6_addr(ziti_address *za, const struct in6_addr *a);
extern void ip4_addr_from_in_addr(ip4_addr_t *ip, const struct in_addr *a);
extern void ip6_addr_from_in6_addr(ip6_addr_t *ip, const struct in6_addr *a);
/** convert from socket address types */
extern bool ziti_address_from_sockaddr(ziti_address *za, const struct sockaddr *sa);
extern void ziti_address_from_sockaddr_in(ziti_address *za, const struct sockaddr_in *sin);
extern void ziti_address_from_sockaddr_in6(ziti_address *za, const struct sockaddr_in6 *sin6);
extern bool ip_addr_from_sockaddr(ip_addr_t *ip, u16_t *port, const struct sockaddr *sa);
extern void ip4_addr_from_sockaddr_in(ip4_addr_t *ip, u16_t *port, const struct sockaddr_in *sin);
extern void ip6_addr_from_sockaddr_in6(ip6_addr_t *ip, u16_t *port, const struct sockaddr_in6 *sin6);
/** convert from lwip ip_addr types */
extern bool ziti_address_from_ip_addr(ziti_address *zaddr, const ip_addr_t *ip);
extern void ziti_address_from_ip4_addr(ziti_address *za, const ip4_addr_t *ip4);
extern void ziti_address_from_ip6_addr(ziti_address *za, const ip6_addr_t *ip6);

extern bool protocol_match(const char *protocol, const protocol_list_t *protocols);
extern const ziti_address * address_match(const ziti_address *addr, const address_list_t *addresses);
extern const port_range_t *port_match(int port, const port_range_list_t *port_ranges);

extern tunneler_context ziti_tunneler_init(tunneler_sdk_options *opts, uv_loop_t *loop);
extern tunneler_context ziti_tunneler_init_host_only(tunneler_sdk_options *opts, uv_loop_t *loop);

extern void ziti_tunneler_exclude_route(tunneler_context tnlr_ctx, const char* dst);
extern void ziti_tunnel_commit_routes(tunneler_context tnlr_ctx);

/** called by tunneler application when it is done with a tunneler_context.
 * calls `stop_intercepting` for each intercepted service. */
extern void ziti_tunneler_shutdown(tunneler_context tnlr_ctx);

extern int ziti_tunneler_intercept(tunneler_context tnlr_ctx, intercept_ctx_t *i_ctx);

extern host_ctx_t * ziti_tunneler_host(tunneler_context tnlr_ctx, const void *ziti_ctx, const char *service_name, cfg_type_e cfg_type, void *cfg);

extern void ziti_tunneler_stop_intercepting(tunneler_context tnlr_ctx, void *zi_ctx);

extern intercept_ctx_t * ziti_tunnel_find_intercept(tunneler_context tnlr_ctx, void *zi_ctx);

extern void ziti_tunneler_set_idle_timeout(struct io_ctx_s *io_context, unsigned int timeout);

extern void ziti_tunneler_dial_completed(struct io_ctx_s *io_context, bool ok);

extern ssize_t ziti_tunneler_write(tunneler_io_context tnlr_io_ctx, const void *data, size_t len);

struct write_ctx_s;
extern void ziti_tunneler_ack(struct write_ctx_s *write_ctx);

extern int ziti_tunneler_close(tunneler_io_context tnlr_io_ctx);

extern int ziti_tunneler_close_write(tunneler_io_context tnlr_io_ctx);

extern const char* ziti_tunneler_version();

extern const char* ziti_tunneler_build_date();

extern void ziti_tunnel_set_logger(tunnel_logger_f logger);
extern void ziti_tunnel_set_log_level(int lvl);

typedef void (*ziti_tunnel_async_fn)(uv_loop_t *loop, void *ctx);
extern void ziti_tunnel_async_send(tunneler_context tctx, ziti_tunnel_async_fn f, void *arg);


#define TNL_IP_MEM_POOL(XX, ...) \
XX(name, model_string, none, Name, __VA_ARGS__) \
XX(max, model_number, none, Max, __VA_ARGS__) \
XX(used, model_number, none, Used, __VA_ARGS__) \
XX(avail, model_number, none, Avail, __VA_ARGS__)

#define TNL_IP_CONN(XX, ...) \
XX(protocol, model_string, none, Protocol, __VA_ARGS__) \
XX(local_ip, model_string, none, LocalIP, __VA_ARGS__) \
XX(local_port, model_number, none, LocalPort, __VA_ARGS__) \
XX(remote_ip, model_string, none, RemoteIP, __VA_ARGS__) \
XX(remote_port, model_number, none, RemotePort, __VA_ARGS__) \
XX(state, model_string, none, State, __VA_ARGS__) \
XX(service, model_string, none, Service, __VA_ARGS__)

#define TNL_IP_STATS(XX, ...) \
XX(pools, tunnel_ip_mem_pool, array, Pools, __VA_ARGS__) \
XX(connections, tunnel_ip_conn, array, Connections, __VA_ARGS__)

DECLARE_MODEL(tunnel_ip_mem_pool, TNL_IP_MEM_POOL)
DECLARE_MODEL(tunnel_ip_conn, TNL_IP_CONN)
DECLARE_MODEL(tunnel_ip_stats, TNL_IP_STATS)

extern void ziti_tunnel_get_ip_stats(tunnel_ip_stats *stats);

#ifdef __cplusplus
}
#endif

#endif /* ZITI_TUNNELER_SDK_ZITI_TUNNEL_H */