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

#ifndef ZITI_TUNNEL_SDK_C_CONFIG_UTILS_H
#define ZITI_TUNNEL_SDK_C_CONFIG_UTILS_H
#include <stdbool.h>
#include <uv.h>

typedef struct proxy_endpoint_s {
    char host[128];
    char port[6];
    bool has_auth;
    char user[128];
    char passwd[128];
} proxy_endpoint;

void update_identity_config(uv_loop_t *l, const char *identifier, const char *cfg_json);
char* resolve_directory(const char* path);

int parse_proxy_url(const char *url, proxy_endpoint *endpoint, char *err, size_t err_len);

#endif //ZITI_TUNNEL_SDK_C_CONFIG_UTILS_H
