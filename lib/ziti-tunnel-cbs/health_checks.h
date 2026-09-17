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

#ifndef ZITI_TUNNEL_SDK_C_HEALTH_CHECKS_H
#define ZITI_TUNNEL_SDK_C_HEALTH_CHECKS_H

#include "ziti_hosting.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct health_checks_ctx_s health_checks_ctx_t;

/**
 * Start running the portChecks/httpChecks declared in host_ctx's host.v1 config, if any.
 * Returns NULL (a harmless no-op) if host_ctx is not HOST_CFG_V1, or its config declares
 * no checks. Must be called only after host_ctx->serv is a live, bound connection --
 * check results are applied via ziti_update_terminator()/ziti_send_health_event(), both
 * of which require a bound server connection.
 *
 * The returned handle must eventually be passed to host_health_checks_stop().
 */
health_checks_ctx_t *host_health_checks_start(struct hosted_service_ctx_s *host_ctx);

/**
 * Stop all outstanding timers/requests owned by hc, and free it once they have all
 * closed. Safe to call with hc == NULL. hc must not be used again after this call.
 */
void host_health_checks_stop(health_checks_ctx_t *hc);

#ifdef __cplusplus
}
#endif

#endif //ZITI_TUNNEL_SDK_C_HEALTH_CHECKS_H
