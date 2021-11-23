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

#ifndef ZITI_TUNNEL_SDK_C_INSTANCE_H
#define ZITI_TUNNEL_SDK_C_INSTANCE_H

#include <ziti/ziti_model.h>
#include "model/dtos.h"

#ifdef __cplusplus
extern "C" {
#endif

extern tunnel_identity *find_tunnel_identity(char* identifier);

extern tunnel_identity *get_tunnel_identity(char* identifier);

extern void set_mfa_status(char* identifier, bool mfa_enabled, bool mfa_needed);

extern void update_mfa_time(char* identifier);

extern tunnel_service *get_tunnel_service(tunnel_identity* identifier, ziti_service* zs);

extern tunnel_service *find_tunnel_service(tunnel_identity* id, char* svc_id);

extern void add_or_remove_services_from_tunnel(tunnel_identity *id, tunnel_service_array added_services, tunnel_service_array removed_services);

extern tunnel_status *get_tunnel_status();

extern tunnel_identity_array get_tunnel_identities();

extern int get_remaining_timeout(int timeout, int timeout_rem, tunnel_identity *tnl_id);

#ifdef __cplusplus
}
#endif

#endif //ZITI_TUNNEL_SDK_C_INSTANCE_H
