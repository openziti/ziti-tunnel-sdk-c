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

#ifndef ZITI_TUNNEL_SDK_C_ZITI_INSTANCE_H
#define ZITI_TUNNEL_SDK_C_ZITI_INSTANCE_H

#include <ziti/ziti_tunnel_cbs.h>

static struct cmd_ctx_s {
    ziti_tunnel_ctrl ctrl;
    tunneler_context tunnel_ctx;
    event_cb on_event;
    uv_loop_t *loop;
    ziti_enroll_key_cb enroll_key_cb;
    void *enroll_key_ctx;
    bool intercept_only;
    char *dump_dir;
    char *dump_instance;
} CMD_CTX;

struct mfa_request_s {
    ziti_context ztx;

    // ziti_ar_mfa_cb submit_f;
    void *submit_ctx;

    command_cb cmd_cb;
    void *cmd_ctx;

    // TODO maybe for getting all outstanding MFA reqs
    // LIST_ENTRY(mfa_request_s) _next;
};

typedef struct ziti_intercept_s ziti_intercept_t;
typedef struct ziti_host_s ziti_host_t;

/** how apply_intercept_only() asks the SDK for a service again, as ziti_service_available() does */
typedef int (*service_lookup_fn)(ziti_context ztx, const char *service, ziti_service_cb cb, void *ctx);

/** brings the identity's hosting in line with the tunneler's intercept-only mode: stops its hosts when the mode is
 *  on, and when it is off asks `lookup` again for the services it held back, handing each answer to `rehost`.
 *  returns the number of services it asked for. */
size_t apply_intercept_only(struct ziti_instance_s *inst, tunneler_context tnlr_ctx, service_lookup_fn lookup,
                            ziti_service_cb rehost);

ziti_connection intercept_resolve_connect(ziti_intercept_t *intercept, void *ctx, ziti_conn_cb conn_cb, ziti_data_cb data_cb);

#endif //ZITI_TUNNEL_SDK_C_ZITI_INSTANCE_H
