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

#ifndef ZITI_TUNNEL_SDK_C_INSTANCE_CONFIG_H
#define ZITI_TUNNEL_SDK_C_INSTANCE_CONFIG_H

#include <ziti/ziti_tunnel_cbs.h>

typedef char * (*to_json_fn)(const void * msg, int flags, size_t *len);

bool load_tunnel_status_from_file(uv_loop_t *ziti_loop);
bool save_tunnel_status_to_file();
void initialize_instance_config();
void cleanup_instance_config();

bool process_tunnel_commands(const tunnel_command *tnl_cmd, command_cb cb, void *ctx);
void send_tunnel_command(const tunnel_command *tnl_cmd, void *ctx);

void send_events_message(const void *message, to_json_fn to_json_f, bool displayEvent);

extern uv_loop_t *global_loop_ref;

#define CHECK_UV(op) do{ \
int uv_rc = (op);    \
if (uv_rc != 0) {    \
ZITI_LOG(WARN, "failed to open IPC socket op=[%s] err=%d[%s]", #op, uv_rc, uv_strerror(uv_rc));\
goto uv_err; \
}                    \
} while(0)


#endif //ZITI_TUNNEL_SDK_C_INSTANCE_CONFIG_H
