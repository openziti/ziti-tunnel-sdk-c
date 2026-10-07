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

//
// Created by eugene on 9/20/21.
//

#ifndef ZITI_TUNNEL_SDK_C_ZITI_HOSTING_H
#define ZITI_TUNNEL_SDK_C_ZITI_HOSTING_H
#include <ziti/ziti_tunnel.h>
#include "ziti/ziti_tunnel_cbs.h"
#include "tlsuv/http.h"
// allowed address is one of:
// - ip subnet address
// - DNS name or wildcard
struct allowed_hostname_s {
    char *domain_name;

    LIST_ENTRY(allowed_hostname_s) _next;
};

typedef LIST_HEAD(allowed_addr_list, allowed_hostname_s) allowed_hostnames_t;

// opaque; defined in health_checks.c. Kept as a forward declaration here (rather than
// including health_checks.h) so this header doesn't need to know about the health check
// engine's internals -- health_checks.h includes this header, not the other way around.
struct health_checks_ctx_s;

struct hosted_service_ctx_s {
    char *       service_name;
    const void * ziti_ctx;
    tunneler_context tnlr_ctx;
    cfg_type_e   cfg_type;
    const void * cfg;
    char display_address[64];
    bool forward_protocol;
    union {
        protocol_list_t allowed_protocols;
        const char *protocol;
    } proto_u;
    bool forward_address;
    union {
        struct {
            address_list_t allowed_addresses;
            allowed_hostnames_t allowed_hostnames;
            ziti_address_translation_array translations;
        };
        const char *address;
    } addr_u;
    bool forward_port;
    union {
        port_range_list_t allowed_port_ranges;
        uint16_t port;
    } port_u;
    address_list_t    allowed_source_addresses;
    const char *proxy_addr;
    tlsuv_connector_t *proxy_connector;
    tlsuv_connector_t *connector;

    // set by hosted_listen_cb() once the bind succeeds; used by the health check engine
    // to push cost/precedence updates and health events for this hosted service.
    ziti_connection serv;
    // the cost/precedence in effect before any health check has run (from listenOptions,
    // defaulted otherwise) -- the health check engine treats this as the floor/reset
    // value for "decrease cost"/"mark healthy" actions.
    uint16_t health_baseline_cost;
    uint8_t  health_baseline_precedence;
    struct health_checks_ctx_s *health_checks;
};

struct tunneled_service_s {
    intercept_ctx_t *intercept;
    host_ctx_t      *host;
};

void accept_resolver_conn(ziti_connection conn, allowed_hostnames_t *allowed);

/**
 * Tears down a hosted_service_ctx_s: frees its members and the ctx itself. cfg is not
 * freed here -- it's a pointer borrowed from the ziti_host_t that owns it (see
 * ziti_tunnel_cbs.c's free_ziti_host()). Normally reached via
 * ziti_close(serv, ziti_hosted_serv_conn_close_cb); ziti_tunnel_cbs.c's stop_hosting()
 * calls it directly instead when there's no live connection to hang a close callback off
 * of (bind never completed, or the connection already closed on its own). Safe to call
 * with NULL.
 */
void free_hosted_service_ctx(struct hosted_service_ctx_s *hosted_ctx);

#endif //ZITI_TUNNEL_SDK_C_ZITI_HOSTING_H
