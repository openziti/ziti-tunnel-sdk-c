/*
 Copyright 2019-2021 NetFoundry Inc.

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

struct ziti_instance_s {
    char *identifier;
    ziti_options opts;
    command_cb load_cb;
    void *load_ctx;

    ziti_context ztx;
    struct mfa_request_s *mfa_req;
    model_map intercepts;
    LIST_ENTRY(ziti_instance_s) _next;
};

typedef struct ziti_intercept_s ziti_intercept_t;

#endif //ZITI_TUNNEL_SDK_C_ZITI_INSTANCE_H
