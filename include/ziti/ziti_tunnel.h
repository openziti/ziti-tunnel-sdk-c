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
#include "uv_mbed/queue.h"
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
    tunneler_io_context   tnlr_io;
    void *                ziti_io; // context specific to ziti SDK being used by the app.
    const void *          ziti_ctx;
};

struct io_ctx_list_entry_s {
    struct io_ctx_s *io;
    SLIST_ENTRY(io_ctx_list_entry_s) entries;
};
SLIST_HEAD(io_ctx_list_s, io_ctx_list_entry_s);

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
typedef void * (*ziti_sdk_dial_cb)(const intercept_ctx_t *intercept_ctx, struct io_ctx_s *io);
typedef int (*ziti_sdk_close_cb)(void *ziti_io_ctx);
typedef ssize_t (*ziti_sdk_write_cb)(const void *ziti_io_ctx, void *write_ctx, const void *data, size_t len);
typedef void (*ziti_sdk_host_v1_cb)(void *ziti_ctx, uv_loop_t *loop, const char *service_name, const char *proto, const char *hostname, int port);

typedef struct tunneler_sdk_options_s {
    netif_driver   netif_driver;
    ziti_sdk_dial_cb    ziti_dial;
    ziti_sdk_close_cb   ziti_close;
    ziti_sdk_close_cb   ziti_close_write;
    ziti_sdk_write_cb   ziti_write;
    ziti_sdk_host_v1_cb ziti_host_v1;
} tunneler_sdk_options;

typedef struct dns_manager_s dns_manager;

typedef int (*fallback_cb)(const char *name, void *ctx, struct in_addr* addr);

typedef void (*dns_answer_cb)(uint8_t *a_packet, size_t a_len, void *ctx);
typedef int (*dns_query)(dns_manager *dns, const uint8_t *q_packet, size_t q_len, dns_answer_cb cb, void *ctx);

struct dns_manager_s {
    bool internal_dns;
    uint32_t dns_ip;
    uint16_t dns_port;

    int (*apply)(dns_manager *dns, const char *host, const char *ip);
    dns_query query;

    uv_loop_t *loop;
    fallback_cb fb_cb;
    void *fb_ctx;
    void *data;
};

// fallback will be called on the worker thread to avoid blocking event loop
extern dns_manager *get_tunneler_dns(uv_loop_t *l, uint32_t dns_ip, fallback_cb cb, void *ctx);

extern tunneler_context ziti_tunneler_init(tunneler_sdk_options *opts, uv_loop_t *loop);

extern void ziti_tunneler_set_dns(tunneler_context tnlr_ctx, dns_manager *dns);

extern int ziti_tunneler_intercept_v1(tunneler_context tnlr_ctx, const void *ziti_ctx, const char *service_id, const char *service_name, const char *hostname, int port);

extern int ziti_tunneler_host_v1(tunneler_context tnlr_ctx, const void *ziti_ctx, const char *service_name, const char *protocol, const char *hostname, int port);

extern void ziti_tunneler_stop_intercepting(tunneler_context tnlr_ctx, const char *service_id);

extern void ziti_tunneler_dial_completed(struct io_ctx_s *io_context, bool ok);

extern ssize_t ziti_tunneler_write(tunneler_io_context tnlr_io_ctx, const void *data, size_t len);

struct write_ctx_s;
extern void ziti_tunneler_ack(struct write_ctx_s *write_ctx);

extern int ziti_tunneler_close(tunneler_io_context tnlr_io_ctx);

extern int ziti_tunneler_close_write(tunneler_io_context tnlr_io_ctx);

extern const char* ziti_tunneler_version();

extern void ziti_tunneler_init_dns(uint32_t mask, int bits);

#ifdef __cplusplus
}
#endif

#endif /* ZITI_TUNNELER_SDK_ZITI_TUNNEL_H */