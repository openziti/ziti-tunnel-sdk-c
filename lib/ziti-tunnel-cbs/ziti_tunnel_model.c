/*
 Copyright 2024 NetFoundry Inc.

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

#include <ziti/ziti_tunnel_cbs.h>

// ******* TUNNEL MODEL
IMPL_MODEL(tunnel_service_control, TUNNEL_SERVICE_CONTROL)
IMPL_MODEL(tunnel_set_log_level, TUNNEL_SET_LOG_LEVEL)
IMPL_MODEL(tunnel_tun_ip_v4, TUNNEL_TUN_IP_V4)
IMPL_MODEL(tunnel_add_identity, TUNNEL_ADD_IDENTITY)
IMPL_MODEL(tunnel_ext_auth, TUNNEL_EXT_AUTH)
IMPL_MODEL(tunnel_upstream_dns, TUNNEL_UPSTREAM_DNS)