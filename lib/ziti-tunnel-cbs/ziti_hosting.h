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
#include "tlsuv/http.h"
// allowed address is one of:
// - ip subnet address
// - DNS name or wildcard
struct allowed_hostname_s {
    char *domain_name;

    LIST_ENTRY(allowed_hostname_s) _next;
};

typedef LIST_HEAD(allowed_addr_list, allowed_hostname_s) allowed_hostnames_t;

typedef struct address_translation_s {
    address_t from;
    address_t to;
    STAILQ_ENTRY(address_translation_s) entries;
} address_translation_t;

typedef STAILQ_HEAD(address_translation_list_s, address_translation_s) address_translation_list_t;

struct hosted_service_ctx_s {
    char *       service_name;
    const void * ziti_ctx;
    uv_loop_t *  loop;
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
            address_translation_list_t translations;
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
};

struct tunneled_service_s {
    intercept_ctx_t *intercept;
    host_ctx_t      *host;
};

void accept_resolver_conn(ziti_connection conn, allowed_hostnames_t *allowed);

#endif //ZITI_TUNNEL_SDK_C_ZITI_HOSTING_H
