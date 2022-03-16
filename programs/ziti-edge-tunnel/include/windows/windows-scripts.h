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

#ifndef ZITI_TUNNEL_SDK_C_WINDOWS_SCRIPTS_H
#define ZITI_TUNNEL_SDK_C_WINDOWS_SCRIPTS_H

#define MAX_POWERSHELL_COMMAND_LEN 8192
#define MAX_POWERSHELL_SCRIPT_LEN 7500 //represents how long the powershell script can be. as of apr 2021 the limit was 8k (8192). leaves a little room for the rest of the script
#ifndef MAXBUFFERLEN
#define MAXBUFFERLEN 8192
#endif
#ifndef BUFFER_SIZE
#define BUFFER_SIZE 1024
#endif

#include "ziti/model_support.h"

void add_nrpt_rules(uv_loop_t *nrpt_loop, model_map *hostnames, const char* dns_ip);
void remove_nrpt_rules(uv_loop_t *nrpt_loop, model_map *hostnames);
void remove_all_nrpt_rules();
bool is_nrpt_policies_effective(char* tns_ip);
model_map *get_connection_specific_domains();
void remove_and_add_nrpt_rules(uv_loop_t *nrpt_loop, model_map *hostnames, const char* dns_ip);
void update_interface_metric(uv_loop_t *ziti_loop, char* tun_name, int metric);
void update_symlink(uv_loop_t *symlink_loop, char* symlink, char* filename);

#endif //ZITI_TUNNEL_SDK_C_WINDOWS_SCRIPTS_H
