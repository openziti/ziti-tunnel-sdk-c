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

#ifndef NF_ZITI_TUNNELER_SDK_ZITI_TUNNELER_H
#define NF_ZITI_TUNNELER_SDK_ZITI_TUNNELER_H

#include <stdbool.h>
#include "uv.h"
#include "nf/netif_driver.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tunneler_ctx_s *tunneler_context;
typedef struct tunneler_io_ctx_s *tunneler_io_context;

/** data needed to dial a ziti service when a client connection is intercepted */
typedef struct intercept_ctx_s{
    const char *  service_name;
    const void *  ziti_ctx;
} intercept_ctx_t;

struct io_ctx_s {
    tunneler_io_context  tnlr_io_ctx;
    void *               ziti_io_ctx; // context specific to ziti SDK being used by the app.
};

/**
 * called when a client connection is intercepted.
 * implementations are expected to dial the service and return
 * context that will be passed to ziti_read/ziti_write */
typedef void * (*ziti_dial_cb)(const intercept_ctx_t *intercept_ctx, tunneler_io_context tnlr_io_ctx);
typedef void (*ziti_close_cb)(void *ziti_io_ctx);
typedef ssize_t (*ziti_write_cb)(const void *ziti_io_ctx, void *write_ctx, const void *data, size_t len);

typedef struct tunneler_sdk_options_s {
    netif_driver   netif_driver;
    ziti_dial_cb   ziti_dial;
    ziti_close_cb  ziti_close;
    ziti_write_cb  ziti_write;
} tunneler_sdk_options;

extern tunneler_context NF_tunneler_init(tunneler_sdk_options *opts, uv_loop_t *loop);

extern int NF_tunneler_intercept_v1(tunneler_context tnlr_ctx, const void *ziti_ctx, const char *service_name, const char *hostname, int port);

extern void NF_tunneler_stop_intercepting(tunneler_context tnlr_ctx, const char *service_name);

extern void NF_tunneler_dial_completed(tunneler_io_context *tnlr_io_ctx, void *ziti_io_ctx, bool ok);

extern int NF_tunneler_write(tunneler_io_context *tnlr_io_ctx, const void *data, size_t len);

struct write_ctx_s;
extern void NF_tunneler_ack(struct write_ctx_s *write_ctx);

extern int NF_tunneler_close(tunneler_io_context *tnlr_io_ctx);

#ifdef __cplusplus
}
#endif

#endif /* NF_ZITI_TUNNELER_SDK_ZITI_TUNNELER_H */