/*
Copyright NetFoundry, Inc.

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
#include "ziti/netif_driver.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tunneler_ctx_s *tunneler_context;
typedef struct tunneler_io_ctx_s *tunneler_io_context;
typedef struct hosted_io_ctx_s *hosted_io_context;

/** data needed to dial a ziti service when a client connection is intercepted */
typedef struct intercept_ctx_s {
    const char *  service_id;
    const char *  service_name;
    const void *  ziti_ctx;
} intercept_ctx_t;

struct io_ctx_s {
    tunneler_io_context * tnlr_io_ctx_p; // use pointer to allow tsdk and zsdk callbacks to see when context is nulled.
    void *                ziti_io_ctx; // context specific to ziti SDK being used by the app.
};

typedef struct hosted_service_ctx_s {
    char *       service_name;
    char *       proto;
    int          proto_id;
    char *       hostname;
    int          port;
    void *       ziti_ctx;
    uv_loop_t *  loop;
} *hosted_service_context;

/**
 * called when a client connection is intercepted.
 * implementations are expected to dial the service and return
 * context that will be passed to ziti_read/ziti_write */
typedef void * (*ziti_sdk_dial_cb)(const intercept_ctx_t *intercept_ctx, tunneler_io_context tnlr_io_ctx);
typedef int (*ziti_sdk_close_cb)(void *ziti_io_ctx);
typedef ssize_t (*ziti_sdk_write_cb)(const void *ziti_io_ctx, void *write_ctx, const void *data, size_t len);
typedef void (*ziti_sdk_host_v1_cb)(void *ziti_ctx, uv_loop_t *loop, const char *service_name, const char *proto, const char *hostname, int port);

typedef struct tunneler_sdk_options_s {
    netif_driver   netif_driver;
    ziti_sdk_dial_cb    ziti_dial;
    ziti_sdk_close_cb   ziti_close;
    ziti_sdk_write_cb   ziti_write;
    ziti_sdk_host_v1_cb ziti_host_v1;
} tunneler_sdk_options;

typedef struct dns_manager_s dns_manager;
struct dns_manager_s {
    int (*apply)(dns_manager *dns, const char *host, const char *ip);
    void *data;
};

extern tunneler_context ziti_tunneler_init(tunneler_sdk_options *opts, uv_loop_t *loop);

extern void ziti_tunneler_set_dns(tunneler_context tnlr_ctx, dns_manager *dns);

extern int ziti_tunneler_intercept_v1(tunneler_context tnlr_ctx, const void *ziti_ctx, const char *service_id, const char *service_name, const char *hostname, int port);

typedef struct port_range_s {
    int low;
    int high;
} port_range_t;

extern int ziti_tunneler_intercept_v2(tunneler_context tnlr_ctx, const void *ziti_ctx, const char *service_id, const char *service_name,
                                      const char **protocols, const char **addresses, int *ports, port_range_t *port_ranges,
                                      const char *dial_identity, int dial_timeout);

extern int ziti_tunneler_host_v1(tunneler_context tnlr_ctx, const void *ziti_ctx, const char *service_name, const char *protocol, const char *hostname, int port);

extern void ziti_tunneler_stop_intercepting(tunneler_context tnlr_ctx, const char *service_id);

extern void ziti_tunneler_dial_completed(tunneler_io_context *tnlr_io_ctx, void *ziti_io_ctx, bool ok);

extern ssize_t ziti_tunneler_write(tunneler_io_context *tnlr_io_ctx, const void *data, size_t len);

struct write_ctx_s;
extern void ziti_tunneler_ack(struct write_ctx_s *write_ctx);

extern int ziti_tunneler_close(tunneler_io_context *tnlr_io_ctx);

extern int ziti_tunneler_close_write(tunneler_io_context *tnlr_io_ctx);

extern const char* ziti_tunneler_version();

extern void ziti_tunneler_init_dns(uint32_t mask, int bits);

#ifdef __cplusplus
}
#endif

#endif /* ZITI_TUNNELER_SDK_ZITI_TUNNEL_H */