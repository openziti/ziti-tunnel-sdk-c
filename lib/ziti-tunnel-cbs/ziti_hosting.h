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

//
// Created by eugene on 9/20/21.
//

#ifndef ZITI_TUNNEL_SDK_C_ZITI_HOSTING_H
#define ZITI_TUNNEL_SDK_C_ZITI_HOSTING_H

// allowed address is one of:
// - ip subnet address
// - DNS name or wildcard
struct allowed_hostname_s {
    char *domain_name;

    LIST_ENTRY(allowed_hostname_s) _next;
};

typedef LIST_HEAD(allowed_addr_list, allowed_hostname_s) allowed_hostnames_t;

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
        char *protocol;
    } proto_u;
    bool forward_address;
    union {
        struct {
            address_list_t allowed_addresses;
            allowed_hostnames_t allowed_hostnames;
        };
        char *address;
    } addr_u;
    bool forward_port;
    union {
        port_range_list_t allowed_port_ranges;
        uint16_t port;
    } port_u;
    address_list_t    allowed_source_addresses;
};

struct tunneled_service_s {
    intercept_ctx_t *intercept;
    host_ctx_t      *host;
};

#endif //ZITI_TUNNEL_SDK_C_ZITI_HOSTING_H
