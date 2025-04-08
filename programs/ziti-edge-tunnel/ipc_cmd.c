// Copyright NetFoundry Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <json-c/json_tokener.h>
#include <stdlib.h>
#include <uv.h>
#include <tlsuv/queue.h>
#include <ziti/ziti_log.h>
#include <ziti/ziti_tunnel_cbs.h>
#if _WIN32
#include "windows/windows-scripts.h"
#endif

#include "identity-utils.h"
#include "instance-config.h"

extern const ziti_tunnel_ctrl *CMD_CTRL;

static uv_pipe_t cmd_server;

struct ipc_conn_s {
    uv_pipe_t ipc;
    int cmds;
    LIST_ENTRY(ipc_conn_s) _next_ipc_cmd;
};
// list to store the ipc connections
static LIST_HEAD(ipc_list, ipc_conn_s) ipc_clients_list = LIST_HEAD_INITIALIZER(ipc_clients_list);

static int sizeof_ipc_clients_list() {
    struct ipc_conn_s *ipc_client;
    int size = 0;
    LIST_FOREACH(ipc_client, &ipc_clients_list, _next_ipc_cmd) {
        size++;
    }
    return size;
}

static void tnl_transfer_rates(const tunnel_identity_metrics *metrics, void *ctx) {
    tunnel_identity *tnl_id = ctx;
    if (metrics->up != NULL) {
        tnl_id->Metrics.Up = (int) strtol(metrics->up, NULL, 10);
    }
    if (metrics->down != NULL) {
        tnl_id->Metrics.Down = (int) strtol(metrics->down, NULL, 10);
    }
}

static void cmd_alloc(uv_handle_t *s, size_t sugg, uv_buf_t *b) {
    b->base = malloc(sugg);
    b->len = sugg;
}

static void on_command_inline_resp(const tunnel_result* result, void *ctx) {
    tunnel_command_inline *tnl_cmd_inline = ctx;

    if (tnl_cmd_inline == NULL) {
        return;
    }

    if (result->data != NULL && strlen(result->data) > 0) {
        switch (tnl_cmd_inline->command) {
        case TunnelCommand_GetMetrics: {
                if (result->success) {
                    tunnel_identity_metrics id_metrics = {0};
                    if (parse_tunnel_identity_metrics(&id_metrics, result->data, strlen(result->data)) < 0) {
                        ZITI_LOG(ERROR, "Could not fetch metrics data");
                    } else {
                        tunnel_identity *tnl_id = find_tunnel_identity(tnl_cmd_inline->identifier);
                        tnl_transfer_rates(&id_metrics, tnl_id);
                    }
                    free_tunnel_identity_metrics(&id_metrics);
                }
                break;
        }
        default: {
                ZITI_LOG(ERROR, "Tunnel command not supported %d", tnl_cmd_inline->command);
        }
        }
    }

    if (tnl_cmd_inline != NULL) {
        free_tunnel_command_inline(tnl_cmd_inline);
        free(tnl_cmd_inline);
    }
}

static void close_ipc(struct ipc_conn_s *ipc_client, const char *msg) {
    if (ipc_client->cmds != 0) {
        ZITI_LOG(DEBUG, "waiting for completion: %d commands in progress", ipc_client->cmds);
    } else {
        LIST_REMOVE(ipc_client, _next_ipc_cmd);
        ZITI_LOG(DEBUG, "closing client: %s", msg ? msg : "OK");
        if (ipc_client->ipc.data) json_tokener_free(ipc_client->ipc.data);
        uv_close((uv_handle_t *) &ipc_client->ipc, (uv_close_cb) free);
    }
}

static void on_cmd_write(uv_write_t *wr, int len) {
    uv_stream_t *s = wr->handle;
    struct ipc_conn_s *ipc_client = (struct ipc_conn_s*)s;
    ipc_client->cmds -= 1;

    ZITI_LOG(DEBUG, "IPC write complete");
    if (len < 0) {
        ZITI_LOG(WARN, "failed to write command response");
    }

    if (wr->data) {
        free(wr->data);
    }
    free(wr);

    if (!uv_is_active((const uv_handle_t *) s)) { // peer sent EOF, we can close now
        close_ipc(ipc_client, "EOF received");
    }
}

static void on_command_resp(const tunnel_result* result, void *ctx) {
    struct ipc_conn_s *ipc = ctx;

    if (uv_is_closing((const uv_handle_t *) &ipc->ipc)) {
        ZITI_LOG(WARN, "failed to send command response: handle is closing");
        return;
    }

    size_t json_len;
    char *json = tunnel_result_to_json(result, MODEL_JSON_COMPACT, &json_len);
    ZITI_LOG(TRACE, "resp[%d,len=%zd] = %.*s",
            result->success, json_len, (int)json_len, json);

    if (result->data != NULL) {
        tunnel_command tnl_res_cmd = {0};
        if (parse_tunnel_command(&tnl_res_cmd, result->data, strlen(result->data)) >= 0) {
            switch (tnl_res_cmd.command) {
                case TunnelCommand_RemoveIdentity: {
                    tunnel_identity_id tnl_delete_id;
                    if (tnl_res_cmd.data != NULL && parse_tunnel_identity_id(&tnl_delete_id, tnl_res_cmd.data, strlen(tnl_res_cmd.data)) >= 0) {
                        if (tnl_delete_id.identifier == NULL) {
                            ZITI_LOG(ERROR, "Identity filename is not found in the remove identity request, not deleting the identity file");
                            break;
                        }
#if _WIN32
                        tunnel_identity *id = find_tunnel_identity(tnl_delete_id.identifier);
                        if(id != NULL) {
                            if (id->Services) {
                                model_map hostnamesToRemove = {0};
                                for (int index = 0; id->Services[index]; index++) {
                                    tunnel_service *tnl_svc = id->Services[index];
                                    if (tnl_svc->Addresses != NULL) {
                                        for (int i = 0; tnl_svc->Addresses[i]; i++) {
                                            tunnel_address *addr = tnl_svc->Addresses[i];
                                            if (addr->IsHost &&
                                                model_map_get(&hostnamesToRemove, addr->HostName) == NULL) {
                                                model_map_set(&hostnamesToRemove, addr->HostName, "TRUE");
                                            }
                                        }
                                    }
                                }

                                if (model_map_size(&hostnamesToRemove) > 0) {
                                    remove_nrpt_rules(global_loop_ref, &hostnamesToRemove);
                                }
                            }
                        } else {
                            ZITI_LOG(WARN, "asked to remove identity, but identity was not found: %s", tnl_delete_id.identifier);
                        }
#endif
                        delete_identity_from_instance(tnl_delete_id.identifier);
                        free_tunnel_identity_id(&tnl_delete_id);
                        // should be the last line in this function as it calls the mutex/lock
                        save_tunnel_status_to_file();
                    }

                    break;
                }
                case TunnelCommand_IdentityOnOff: {
                    if (!result->success) {
                        break;
                    }
                    tunnel_on_off_identity on_off_id = {};
                    if (tnl_res_cmd.data && parse_tunnel_on_off_identity(&on_off_id, tnl_res_cmd.data, strlen(tnl_res_cmd.data)) > 0) {
                        set_ziti_status(on_off_id.onOff, on_off_id.identifier);
                        // should be the last line in this function as it calls the mutex/lock
                        save_tunnel_status_to_file();
                    }
                    free_tunnel_on_off_identity(&on_off_id);
                    break;
                }
                case TunnelCommand_Unknown: {
                    break;
                }
            }
        }
        free_tunnel_command(&tnl_res_cmd);
    }

    uv_buf_t buf[2];
    buf[0] = uv_buf_init(json, json_len);
    buf[1] = uv_buf_init("\n", 1);
    uv_write_t *wr = calloc(1, sizeof(*wr));
    wr->data = json;
    int rc = uv_write(wr, (uv_stream_t *) &ipc->ipc, buf, 2, on_cmd_write);
    if (rc < 0) {
        ZITI_LOG(WARN, "failed to write command response");
        free(wr->data);
        free(wr);

    }
}



static void process_ipc_command(struct ipc_conn_s *s, json_object *json) {
    tunnel_command tnl_cmd = {0};
    if (tunnel_command_from_json(&tnl_cmd, json) >= 0) {
        s->cmds += 1;
        // process_tunnel_commands is used to update the log level and the tun ip information in the config file through IPC command.
        // So when the user restarts the tunnel, the new values will be taken.
        // The config file can be modified only from ziti-edge-tunnel.c file.
        int status = process_tunnel_commands(&tnl_cmd, on_command_resp, s);
        if (!status) {
            // process_cmd will delegate the requests to ziti_tunnel_ctrl.c , which is used to perform the operations against the controller.
            // config.file cannot be modified or read from that class
            CMD_CTRL->process(&tnl_cmd, on_command_resp, s);
        }
    } else {
        tunnel_result resp = {
            .success = false,
            .error = "failed to parse command",
            .code = IPC_ERROR,
        };
        on_command_resp(&resp, s);
    }
    free_tunnel_command(&tnl_cmd);
}

static void on_cmd(uv_stream_t *s, ssize_t len, const uv_buf_t *b)
{
    struct ipc_conn_s *ipc_client = (struct ipc_conn_s*)s;
    if (len == UV_EOF) {
        if (s->data && json_tokener_get_error(s->data) == json_tokener_continue) {
            close_ipc(ipc_client, "EOF before completed JSON payload");
            ZITI_LOG(DEBUG, "IPC client connection closed, count: %d", sizeof_ipc_clients_list());
        } else {
            ZITI_LOG(VERBOSE, "EOF on IPC stream");
            close_ipc(ipc_client, "processed all commands");
        }
    } else if (len < 0) {
        ZITI_LOG(WARN, "received from client - %s. Closing connection.", uv_err_name(len));
        close_ipc(ipc_client, uv_strerror((int)len));
        ZITI_LOG(DEBUG, "IPC client connection closed, count: %d", sizeof_ipc_clients_list());
    } else {
        ZITI_LOG(DEBUG, "received cmd <%.*s>", (int) len, b->base);

        json_tokener *parser = s->data;

        size_t processed = 0;
        while (processed < len) {
            json_object *json = json_tokener_parse_ex(parser, b->base + processed, (int) (len - processed));
            size_t end = json_tokener_get_parse_end(parser);
            processed += end;
            if (json) {
                process_ipc_command(s, json);
                json_object_put(json);
                json_tokener_reset(parser);
            } else if (json_tokener_get_error(parser) != json_tokener_continue) {
                ZITI_LOG(ERROR, "failed to parse json command: %s, received[%.*s]",
                         json_tokener_error_desc(json_tokener_get_error(parser)),
                         (int) len, b->base);
                close_ipc(ipc_client, "failed to parse JSON");
                break;
            }
        }
    }

    free(b->base);
}


static void on_cmd_client(uv_stream_t *s, int status) {
    int current_ipc_channels = sizeof_ipc_clients_list();
    struct ipc_conn_s *cmd_conn = calloc(1, sizeof(struct ipc_conn_s));
    cmd_conn->ipc.data = json_tokener_new();
    uv_pipe_init(s->loop, &cmd_conn->ipc, 0);
    uv_accept(s, (uv_stream_t *) &cmd_conn->ipc);
    uv_read_start((uv_stream_t *) &cmd_conn->ipc, cmd_alloc, on_cmd);
    LIST_INSERT_HEAD(&ipc_clients_list, cmd_conn, _next_ipc_cmd);
    ZITI_LOG(DEBUG,"Received IPC client connection request, count: %d", ++current_ipc_channels);
}

int start_cmd_socket(uv_loop_t *l, const char *sockfile) {

    if (uv_is_active((const uv_handle_t *) &cmd_server)) {
        return 0;
    }

    uv_fs_t fs;
    uv_fs_unlink(l, &fs, sockfile, NULL);

    CHECK_UV(uv_pipe_init(l, &cmd_server, 0));
    CHECK_UV(uv_pipe_bind(&cmd_server, sockfile));
    CHECK_UV(uv_pipe_chmod(&cmd_server, UV_WRITABLE | UV_READABLE));

    uv_unref((uv_handle_t *) &cmd_server);

    CHECK_UV(uv_listen((uv_stream_t *) &cmd_server, 0, on_cmd_client));

    return 0;

    uv_err:
    return -1;
}

void send_tunnel_command(const tunnel_command *tnl_cmd, void *ctx) {
    CMD_CTRL->process(tnl_cmd, on_command_resp, ctx);
}

void send_tunnel_command_inline(const tunnel_command *tnl_cmd, void *ctx) {
    CMD_CTRL->process(tnl_cmd, on_command_inline_resp, ctx);
}

