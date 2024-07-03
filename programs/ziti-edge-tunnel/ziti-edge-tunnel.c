/*
 Copyright 2021 NetFoundry Inc.

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

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "uv.h"
#include "ziti/ziti.h"
#include "ziti/ziti_tunnel.h"
#include "ziti/ziti_tunnel_cbs.h"
#include <ziti/ziti_log.h>
#include <ziti/ziti_dns.h>
#include "model/events.h"
#include "identity-utils.h"
#include "instance-config.h"
#include <config-utils.h>
#include <service-utils.h>

#if __APPLE__ && __MACH__
#include "netif_driver/darwin/utun.h"
#elif __linux__
#include "netif_driver/linux/tun.h"
#elif _WIN32
#include <time.h>
#include <io.h>
#include "netif_driver/windows/tun.h"
#include "windows/windows-service.h"
#include "windows/windows-scripts.h"

#define setenv(n,v,o) do {if(o || getenv(n) == NULL) _putenv_s(n,v); } while(0)
#endif

#ifndef MAXIPCCOMMANDLEN
#define MAXIPCCOMMANDLEN (4096 * 4)
#endif

#ifndef MAXMESSAGELEN
#define MAXMESSAGELEN 4096
#endif

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 254

#ifndef S_IRUSR
#define	S_IRUSR		_S_IREAD
#endif
#ifndef S_IWUSR
#define	S_IWUSR	_S_IWRITE
#endif

//functions for logging on windows
bool log_init(uv_loop_t *);
void ziti_log_writer(int , const char *, const char *, size_t);
char* get_log_file_name();
#include <stdint.h>
#endif

static int dns_miss_status = DNS_REFUSE;

typedef char * (*to_json_fn)(const void * msg, int flags, size_t *len);
static void send_events_message(const void *message, to_json_fn to_json_f, bool displayEvent);
static void send_tunnel_command(const tunnel_command *tnl_cmd, void *ctx);
static void send_tunnel_command_inline(const tunnel_command *tnl_cmd, void *ctx);
static void scm_service_stop_event(uv_loop_t *loop, void *arg);
static void stop_tunnel_and_cleanup();
static bool is_host_only();
static bool use_rt_main();
static void run_tunneler_loop(uv_loop_t* ziti_loop);
static tunneler_context initialize_tunneler(netif_driver tun, uv_loop_t* ziti_loop);

#if _WIN32
static void move_config_from_previous_windows_backup(uv_loop_t *loop);
#define LAST_CHAR_IPC_CMD '\n'
#else
#define LAST_CHAR_IPC_CMD '\0'
#endif

struct ipc_cmd_s {
    char *cmd_data;
    int len;
    STAILQ_ENTRY(ipc_cmd_s) _next;
};

typedef STAILQ_HEAD(cmd_q, ipc_cmd_s) ipc_cmd_q;

typedef struct ipc_cmd_ctx_s {
    ipc_cmd_q ipc_cmd_queue;
    uv_mutex_t cmd_lock;
} ipc_cmd_ctx_t;

static ipc_cmd_ctx_t *ipc_cmd_ctx;

struct enroll_cb_params {
    uv_buf_t config; /* out */
};

struct cfg_instance_s {
    char *cfg;
    LIST_ENTRY(cfg_instance_s) _next;
};

// temporary list to pass info between parse and run
static LIST_HEAD(instance_list, cfg_instance_s) load_list;

struct event_conn_s {
    uv_pipe_t *event_client_conn;
    LIST_ENTRY(event_conn_s) _next_event;
};
// list to store the event connections
static LIST_HEAD(events_list, event_conn_s) event_clients_list = LIST_HEAD_INITIALIZER(event_clients_list);

struct ipc_conn_s {
    uv_pipe_t ipc;
    LIST_ENTRY(ipc_conn_s) _next_ipc_cmd;
};
// list to store the ipc connections
static LIST_HEAD(ipc_list, ipc_conn_s) ipc_clients_list = LIST_HEAD_INITIALIZER(ipc_clients_list);

static long refresh_metrics = 5000;
static long metrics_latency = 5000;
static char *configured_cidr = NULL;
static char *configured_log_level = NULL;
static char *configured_proxy = NULL;
static char *config_dir = NULL;

static uv_pipe_t cmd_server;
static uv_pipe_t event_server;

//timer
static uv_timer_t metrics_timer;

// singleton
static const ziti_tunnel_ctrl *CMD_CTRL;

static bool started_by_scm = false;
static bool tunnel_interrupted = false;

uv_loop_t *global_loop_ref = NULL;
tunneler_context tunneler;
static uv_mutex_t stop_mutex;
static uv_cond_t stop_cond;
IMPL_ENUM(event, EVENT_ACTIONS)

#if _WIN32
static char sockfile[] = "\\\\.\\pipe\\ziti-edge-tunnel.sock";
static char eventsockfile[] = "\\\\.\\pipe\\ziti-edge-tunnel-event.sock";
#elif __unix__ || unix || ( __APPLE__ && __MACH__ )
#include <grp.h>
#include <sys/un.h>
#define SOCKET_PATH "/tmp/.ziti"
static char sockfile[] = SOCKET_PATH "/ziti-edge-tunnel.sock";
static char eventsockfile[] = SOCKET_PATH "/ziti-edge-tunnel-event.sock";
#endif

static int sizeof_event_clients_list() {
    struct event_conn_s *event_client;
    int size = 0;
    LIST_FOREACH(event_client, &event_clients_list, _next_event) {
        size++;
    }

    if (size == 0) {
        return size;
    }

    int current_size = size;

    // clean up closed event connection from the list
    for (int idx = 0; idx < size; idx++) {
        struct event_conn_s *del_event_client = NULL;
        LIST_FOREACH(del_event_client, &event_clients_list, _next_event) {
            if (del_event_client->event_client_conn == NULL) {
                break;
            }
        }
        if (del_event_client) {
            LIST_REMOVE(del_event_client, _next_event);
            free(del_event_client);
            current_size--;
        } else {
            // break from for loop
            break;
        }
    }

    return current_size;

}

static int sizeof_ipc_clients_list() {
    struct ipc_conn_s *ipc_client;
    int size = 0;
    LIST_FOREACH(ipc_client, &ipc_clients_list, _next_ipc_cmd) {
        size++;
    }
    return size;
}

static void cmd_alloc(uv_handle_t *s, size_t sugg, uv_buf_t *b) {
    b->base = malloc(sugg);
    b->len = sugg;
}

static void send_tunnel_status(char* status) {
    tunnel_status_event tnl_sts_evt = {0};
    tnl_sts_evt.Op = strdup(status);
    tnl_sts_evt.Status = get_tunnel_status();
    send_events_message(&tnl_sts_evt, (to_json_fn) tunnel_status_event_to_json, true);
    tnl_sts_evt.Status = NULL; //don't free
    free_tunnel_status_event(&tnl_sts_evt);
}

static void on_cmd_write(uv_write_t *wr, int len) {
    if (wr->data) {
        free(wr->data);
    }
    free(wr);
}

static void on_command_resp(const tunnel_result* result, void *ctx) {
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
                    tunnel_on_off_identity on_off_id;
                    if (tnl_res_cmd.data == NULL || parse_tunnel_on_off_identity(&on_off_id, tnl_res_cmd.data, strlen(tnl_res_cmd.data)) < 0) {
                        free_tunnel_on_off_identity(&on_off_id);
                        break;
                    }
                    set_ziti_status(on_off_id.onOff, on_off_id.identifier);
                    // should be the last line in this function as it calls the mutex/lock
                    save_tunnel_status_to_file();
                    break;
                }
                case TunnelCommand_Unknown: {
                    break;
                }
            }
        }
        free_tunnel_command(&tnl_res_cmd);
    }

    if (uv_is_active((const uv_handle_t *) ctx)) {
        uv_buf_t buf;
        size_t data_len = json_len + strlen("\n") + 1;
        buf.base = calloc(data_len, sizeof(char));
        snprintf(buf.base, data_len, "%s\n", json);
        buf.len = strlen(buf.base);
        uv_write_t *wr = calloc(1, sizeof(uv_write_t));
        wr->data = buf.base;
        uv_write(wr, (uv_stream_t *) ctx, &buf, 1, on_cmd_write);
    }
    free(json);
}

void tunnel_enroll_cb(const ziti_config *cfg, int status, const char *err, void *ctx) {
    struct add_identity_request_s *add_id_req = ctx;

    tunnel_result result = {
            .success = false,
            .error = NULL,
            .data = NULL,
            .code = IPC_ERROR,
    };

    if (status != ZITI_OK) {
        ZITI_LOG(ERROR, "enrollment failed: %s(%d)", err, status);
        result.error = "enrollment failed";
        add_id_req->cmd_cb(&result, add_id_req->cmd_ctx);
        free(add_id_req);
        return;
    }

    FILE *f = add_id_req->add_id_ctx;

    size_t len;
    char *cfg_json = ziti_config_to_json(cfg, 0, &len);

    if (fwrite(cfg_json, 1, len, f) != len) {
        ZITI_LOG(ERROR, "failed to write config file");
        fclose(f);
        result.error = "failed to write config file";
        add_id_req->cmd_cb(&result,  add_id_req->cmd_ctx);
        free(add_id_req);
        return;
    }

    free(cfg_json);
    fflush(f);
    fclose(f);

    create_or_get_tunnel_identity(add_id_req->identifier, add_id_req->identifier_file_name);

    // send load identity command to the controller
    tunnel_load_identity load_identity_options = {
            .identifier = add_id_req->identifier,
            .path = add_id_req->identifier,
            .apiPageSize = get_api_page_size(),
    };
    size_t json_len;
    tunnel_command tnl_cmd = {
            .command = TunnelCommand_LoadIdentity,
            .data = tunnel_load_identity_to_json(&load_identity_options, MODEL_JSON_COMPACT, &json_len),
    };
    send_tunnel_command(&tnl_cmd, add_id_req->cmd_ctx);
    free_tunnel_command(&tnl_cmd);
    free(add_id_req);
    save_tunnel_status_to_file();
}

static void enroll_ziti_async(uv_loop_t *loop, void *arg) {
    struct add_identity_request_s *add_id_req = arg;

    ziti_enroll_opts enroll_opts = {0};
    enroll_opts.enroll_name = add_id_req->identifier;
    enroll_opts.jwt_content = add_id_req->jwt_content;
    enroll_opts.use_keychain = add_id_req->use_keychain;

    ziti_enroll(&enroll_opts, loop, tunnel_enroll_cb, add_id_req);
}

static bool process_tunnel_commands(const tunnel_command *tnl_cmd, command_cb cb, void *ctx) {
    tunnel_result result = {
            .success = false,
            .error = NULL,
            .data = NULL,
            .code = IPC_ERROR,
    };
    bool cmd_accepted = false;
    switch (tnl_cmd->command) {
        case TunnelCommand_SetLogLevel: {
            cmd_accepted = true;

            tunnel_set_log_level tunnel_set_log_level_cmd = {0};
            if (tnl_cmd->data == NULL ||
                parse_tunnel_set_log_level(&tunnel_set_log_level_cmd, tnl_cmd->data, strlen(tnl_cmd->data)) < 0 ||
                tunnel_set_log_level_cmd.loglevel == NULL) {
                result.error = "invalid command";
                result.success = false;
                break;
            }

            if (strcasecmp(ziti_log_level_label(), tunnel_set_log_level_cmd.loglevel) != 0) {
                ziti_log_set_level_by_label(tunnel_set_log_level_cmd.loglevel);
                ziti_tunnel_set_log_level(get_log_level(tunnel_set_log_level_cmd.loglevel));
                const char *level = ziti_log_level_label();
                set_log_level(level);
                ZITI_LOG(INFO, "Log level is set to %s", level);
            } else {
                ZITI_LOG(INFO, "Log level is already set to %s", tunnel_set_log_level_cmd.loglevel);
            }
            result.success = true;
            result.code = IPC_SUCCESS;

            break;
        }
        case TunnelCommand_UpdateTunIpv4: {
            cmd_accepted = true;

            tunnel_tun_ip_v4 tunnel_tun_ip_v4_cmd = {0};
            if (tnl_cmd->data == NULL || parse_tunnel_tun_ip_v4(&tunnel_tun_ip_v4_cmd, tnl_cmd->data, strlen(tnl_cmd->data)) < 0) {
                result.error = "invalid command";
                result.success = false;
                free_tunnel_tun_ip_v4(&tunnel_tun_ip_v4_cmd);
                break;
            }
            if (tunnel_tun_ip_v4_cmd.prefixLength < MINTUNPREFIXLENGTH || tunnel_tun_ip_v4_cmd.prefixLength > MAXTUNPREFIXLENGTH) {
                result.error = "prefix length should be between 10 and 18";
                result.success = false;
                break;
            }
            char* tun_ip_str = strdup(tunnel_tun_ip_v4_cmd.tunIP);
            // make a copy, so we can free it later - validating ip address input
            char* tun_ip_cpy = tun_ip_str;
            char* ip_ptr = strtok(tun_ip_str, "."); //cut the string using dot delimiter
            if (ip_ptr == NULL) {
                result.error = "Invalid IP address";
                result.success = false;
                break;
            }
            int dots = 0;
            bool validationStatus = true;
            while (ip_ptr) {
                bool isInt = true;
                char* ip_str = ip_ptr;
                while (*ip_str) {
                    if(!isdigit(*ip_str)){ //if the character is not a number, break
                        isInt = false;
                        validationStatus = false;
                        break;
                    }
                    ip_str++; //point to next character
                }
                if (!isInt) {
                    break;
                }
                int num = atoi(ip_ptr); //convert substring to number
                if (num >= 0 && num <= 255) {
                    ip_ptr = strtok(NULL, "."); //cut the next part of the string
                    if (ip_ptr != NULL)
                        dots++; //increase the dot count
                } else {
                    validationStatus = false;
                    break;
                }
            }
            free(tun_ip_cpy);
            if (dots != 3 || !validationStatus) {
                result.error = "Invalid IP address";
                result.success = false;
                free_tunnel_tun_ip_v4(&tunnel_tun_ip_v4_cmd);
                break;
            }
            if (tunnel_tun_ip_v4_cmd.tunIP == NULL) {
                result.error = "Tun IP is null";
                result.success = false;
                free_tunnel_tun_ip_v4(&tunnel_tun_ip_v4_cmd);
                break;
            }
            set_tun_ipv4_into_instance(tunnel_tun_ip_v4_cmd.tunIP,
                                       (int)tunnel_tun_ip_v4_cmd.prefixLength,
                                       tunnel_tun_ip_v4_cmd.addDns);
            result.success = true;
            result.code = IPC_SUCCESS;
            break;
        }
        case TunnelCommand_Status: {
            cmd_accepted = true;
            tunnel_status* status = get_tunnel_status();
            result.success = true;
            result.code = IPC_SUCCESS;
            size_t json_len;
            result.data = tunnel_status_to_json(status, MODEL_JSON_COMPACT, &json_len);
            break;
        }

        case TunnelCommand_AddIdentity : {
            cmd_accepted = true;
            tunnel_add_identity tunnel_add_identity_cmd = {0};
            if (tnl_cmd->data == NULL ||
                parse_tunnel_add_identity(&tunnel_add_identity_cmd, tnl_cmd->data, strlen(tnl_cmd->data)) < 0 ||
                (tunnel_add_identity_cmd.jwtFileName == NULL && tunnel_add_identity_cmd.jwtContent == NULL)) {
                result.error = "invalid command";
                result.success = false;
                free_tunnel_add_identity(&tunnel_add_identity_cmd);
                break;
            }

            if (tunnel_add_identity_cmd.jwtFileName == NULL) {
                result.error = "identity filename not provided";
                result.success = false;
                break;
            }

            if (tunnel_add_identity_cmd.jwtContent == NULL) {
                result.error = "jwt content not provided";
                result.success = false;
                break;
            }

            if (config_dir == NULL) {
                result.error = "config directory not set";
                result.success = false;
                break;
            }

            char* extension = strstr(tunnel_add_identity_cmd.jwtFileName, ".jwt");
            size_t length;
            if (extension != NULL) {
                length = extension - tunnel_add_identity_cmd.jwtFileName;
            } else {
                length = strlen(tunnel_add_identity_cmd.jwtFileName);
            }
            char new_identifier[FILENAME_MAX] = {0};
            char new_identifier_name[FILENAME_MAX] = {0};
            if ((strlen(config_dir) + length + 6) >  FILENAME_MAX - 1 ) {
                ZITI_LOG(ERROR, "failed to create file %s%c%s.json, The length of the file name is longer than %d", config_dir, PATH_SEP, tunnel_add_identity_cmd.jwtFileName, FILENAME_MAX);
                result.error = "invalid file name";
                result.success = false;
                free_tunnel_add_identity(&tunnel_add_identity_cmd);
                break;
            }
            strncpy(new_identifier_name, tunnel_add_identity_cmd.jwtFileName, length);
            snprintf(new_identifier, FILENAME_MAX, "%s%c%s.json", config_dir, PATH_SEP, new_identifier_name);
            FILE *outfile;
            if ((outfile = fopen(new_identifier, "wb")) == NULL) {
                ZITI_LOG(ERROR, "failed to open file %s: %s(%d)", new_identifier, strerror(errno), errno);
                result.error = "invalid file name";
                result.success = false;
                free_tunnel_add_identity(&tunnel_add_identity_cmd);
                break;
            }

            struct add_identity_request_s *add_id_req = calloc(1, sizeof(struct add_identity_request_s));
            add_id_req->cmd_ctx = ctx;
            add_id_req->cmd_cb = cb;
            add_id_req->add_id_ctx = outfile;
            add_id_req->identifier = strdup(new_identifier);
            add_id_req->identifier_file_name = strdup(new_identifier_name);
            add_id_req->jwt_content = strdup(tunnel_add_identity_cmd.jwtContent);
            add_id_req->use_keychain = tunnel_add_identity_cmd.useKeychain;

            enroll_ziti_async(global_loop_ref, add_id_req);
            free_tunnel_add_identity(&tunnel_add_identity_cmd);
            return true;
        }
#if _WIN32
        case TunnelCommand_ServiceControl: {
            cmd_accepted = true;
            tunnel_service_control tunnel_service_control_opts = {0};
            if (tnl_cmd->data == NULL ||
                parse_tunnel_service_control(&tunnel_service_control_opts, tnl_cmd->data, strlen(tnl_cmd->data)) < 0) {
                result.error = "invalid command";
                result.success = false;
                free_tunnel_service_control(&tunnel_service_control_opts);
                break;
            }
            result.success = true;
            result.code = IPC_SUCCESS;
            if (tunnel_service_control_opts.operation != NULL && strcmp(tunnel_service_control_opts.operation, "stop") == 0) {
                // stops the windows service in scm
                if (!stop_windows_service()) {
                    ZITI_LOG(INFO, "Could not send stop signal to scm, Tunnel must not be started as service");
                    stop_tunnel_and_cleanup();
                    uv_stop(global_loop_ref);
                }
            }
            free_tunnel_service_control(&tunnel_service_control_opts);
            break;
        }
        case TunnelCommand_StatusChange: {
            cmd_accepted = true;
            tunnel_status_change tunnel_status_change_opts = {0};
            if (tnl_cmd->data == NULL ||
                parse_tunnel_status_change(&tunnel_status_change_opts, tnl_cmd->data, strlen(tnl_cmd->data)) < 0) {
                result.error = "invalid command";
                result.success = false;
                free_tunnel_status_change(&tunnel_status_change_opts);
                break;
            }
            result.success = true;
            result.code = IPC_SUCCESS;

            endpoint_status_change(tunnel_status_change_opts.woken, tunnel_status_change_opts.unlocked);

            free_tunnel_status_change(&tunnel_status_change_opts);
        }
#endif
    }
    if (cmd_accepted) {
        cb(&result, ctx);
        if (result.success) {
            // should be the last line in this function as it calls the mutex/lock
            save_tunnel_status_to_file();
        }
        if (result.data) {
            free(result.data);
        }
        return true;
    } else {
        return false;
    }
}

static void process_ipc_command(uv_stream_t *s, json_object *json) {
    tunnel_command tnl_cmd = {0};
    if (tunnel_command_from_json(&tnl_cmd, json) >= 0) {
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


static void on_cmd(uv_stream_t *s, ssize_t len, const uv_buf_t *b) {
    struct ipc_conn_s *ipc_client = (struct ipc_conn_s*)s;
    if (len < 0) {
        if (len != UV_EOF) {
            ZITI_LOG(WARN, "received from client - %s. Closing connection.", uv_err_name(len));
        }

        LIST_REMOVE(ipc_client, _next_ipc_cmd);

        json_tokener *tokener = s->data;
        if (tokener) json_tokener_free(tokener);
        uv_close((uv_handle_t *) &ipc_client->ipc, (uv_close_cb) free);
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
            } else if (json_tokener_get_error(parser) != json_tokener_continue) {
                ZITI_LOG(ERROR, "failed to parse json command: %s, received[%.*s]",
                         json_tokener_error_desc(json_tokener_get_error(parser)),
                         (int) len, b->base);
                json_tokener_free(parser);
                LIST_REMOVE(ipc_client, _next_ipc_cmd);
                uv_close((uv_handle_t *) &ipc_client->ipc, (uv_close_cb) free);
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

static int start_cmd_socket(uv_loop_t *l) {

    if (uv_is_active((const uv_handle_t *) &cmd_server)) {
        return 0;
    }

    uv_fs_t fs;
    uv_fs_unlink(l, &fs, sockfile, NULL);

#define CHECK_UV(op) do{ \
    int uv_rc = (op);    \
    if (uv_rc != 0) {    \
       ZITI_LOG(WARN, "failed to open IPC socket op=[%s] err=%d[%s]", #op, uv_rc, uv_strerror(uv_rc));\
       goto uv_err; \
    }                    \
    } while(0)


    CHECK_UV(uv_pipe_init(l, &cmd_server, 0));
    CHECK_UV(uv_pipe_bind(&cmd_server, sockfile));
    CHECK_UV(uv_pipe_chmod(&cmd_server, UV_WRITABLE | UV_READABLE));

    uv_unref((uv_handle_t *) &cmd_server);

    CHECK_UV(uv_listen((uv_stream_t *) &cmd_server, 0, on_cmd_client));

    return 0;

    uv_err:
    return -1;
}

static void on_events_client(uv_stream_t *s, int status) {
    int current_events_channels = sizeof_event_clients_list();
    uv_pipe_t* event_conn = malloc(sizeof(uv_pipe_t));
    uv_pipe_init(s->loop, event_conn, 0);
    uv_accept(s, (uv_stream_t *) event_conn);
    struct event_conn_s *event_client_conn = calloc(1, sizeof(struct event_conn_s));
    event_client_conn->event_client_conn = event_conn;
    LIST_INSERT_HEAD(&event_clients_list, event_client_conn, _next_event);
    ZITI_LOG(DEBUG,"Received events client connection request, count: %d", ++current_events_channels);

    // send status message immediately
    send_tunnel_status("status");
}


void on_write_event(uv_write_t* req, int status) {
    if (status < 0) {
        ZITI_LOG(ERROR,"Could not sent events message. Write error %s\n", uv_err_name(status));
        if (status == UV_EPIPE) {
            struct event_conn_s *event_client;
            LIST_FOREACH(event_client, &event_clients_list, _next_event) {
                if (event_client->event_client_conn == (uv_pipe_t*) req->handle) {
                    break;
                }
            }
            if (event_client) {
                uv_close((uv_handle_t *) event_client->event_client_conn, (uv_close_cb) free);
                event_client->event_client_conn = NULL;
                int current_event_connection_count = sizeof_event_clients_list();
                ZITI_LOG(WARN,"Events client connection closed, count : %d", current_event_connection_count);

            }

        }
    } else {
        ZITI_LOG(TRACE,"Events message is sent.");
    }
    if (req->data) {
        free(req->data);
    }
    free(req);
}

static void send_events_message(const void *message, to_json_fn to_json_f, bool displayEvent) {
    size_t data_len = 0;
    char *json = to_json_f(message, MODEL_JSON_COMPACT, &data_len);
    if (json == NULL) {
        ZITI_LOG(ERROR, "failed to serialize event");
        return;
    }
    if (displayEvent) {
        ZITI_LOG(DEBUG,"Events Message => %s", json);
    }

    if (!LIST_EMPTY(&event_clients_list)) {
        struct event_conn_s *event_client;
        int events_deleted = 0;
        LIST_FOREACH(event_client, &event_clients_list, _next_event) {
            int err = 0;
            if (event_client->event_client_conn != NULL) {
                uv_buf_t buf;
                data_len = data_len + strlen("\n") + 1;
                buf.base = calloc(data_len, sizeof(char));
                snprintf(buf.base, data_len, "%s\n", json);
                buf.len = strlen(buf.base);
                uv_write_t *wr = calloc(1, sizeof(uv_write_t));
                wr->data = buf.base;
                err = uv_write(wr, (uv_stream_t *)event_client->event_client_conn, &buf, 1, on_write_event);
            }
            if (err < 0){
                ZITI_LOG(ERROR,"Events client write operation failed, received error - %s", uv_err_name(err));
                if (err == UV_EPIPE) {
                    uv_close((uv_handle_t *) event_client->event_client_conn, (uv_close_cb) free);
                    event_client->event_client_conn = NULL;
                    events_deleted++;
                    ZITI_LOG(WARN,"Events client connection closed");
                }
            }
        }
        if (events_deleted > 0) {
            int current_event_connection_count = sizeof_event_clients_list();
            ZITI_LOG(WARN,"Events client connection current count : %d", current_event_connection_count);
        }

    }
    free(json);
}

static int start_event_socket(uv_loop_t *l) {

    if (uv_is_active((const uv_handle_t *) &event_server)) {
        return 0;
    }

    uv_fs_t fs;
    uv_fs_unlink(l, &fs, eventsockfile, NULL);

    CHECK_UV(uv_pipe_init(l, &event_server, 0));
    CHECK_UV(uv_pipe_bind(&event_server, eventsockfile));
    CHECK_UV(uv_pipe_chmod(&event_server, UV_WRITABLE | UV_READABLE));

    uv_unref((uv_handle_t *) &event_server);

    CHECK_UV(uv_listen((uv_stream_t *) &event_server, 0, on_events_client));

    return 0;

    uv_err:
    return -1;
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

static void send_tunnel_command(const tunnel_command *tnl_cmd, void *ctx) {
    CMD_CTRL->process(tnl_cmd, on_command_resp, ctx);
}

static void send_tunnel_command_inline(const tunnel_command *tnl_cmd, void *ctx) {
    CMD_CTRL->process(tnl_cmd, on_command_inline_resp, ctx);
}

static char* addUnit(int count, char* unit) {
    char* result = calloc(MAXMESSAGELEN, sizeof(char));

    if ((count == 1) || (count == 0)) {
        snprintf(result, MAXMESSAGELEN, "%d %s", count, unit);
    } else {
        snprintf(result, MAXMESSAGELEN, "%d %ss", count, unit);
    }
    return result;
}

static char* convert_seconds_to_readable_format(int input) {
    int seconds = input % (60 * 60 * 24);
    int hours = (int)((double) seconds / 60 / 60);
    seconds = input % (60 * 60);
    int minutes = (int)((double) seconds)/ 60;
    seconds = input % 60;
    char* result = calloc(MAXMESSAGELEN, sizeof(char));
    char* hours_unit = NULL;
    char* minutes_unit = NULL;
    char* seconds_unit = NULL;

    if (hours > 0) {
        hours_unit = addUnit(hours, "hour");
        minutes_unit = addUnit(minutes, "minute");
        seconds_unit = addUnit(seconds, "second");
        snprintf(result, MAXMESSAGELEN, "%s %s %s", hours_unit, minutes_unit, seconds_unit);
    } else if (minutes > 0) {
        minutes_unit = addUnit(minutes, "minute");
        seconds_unit = addUnit(seconds, "second");
        snprintf(result, MAXMESSAGELEN, "%s %s", minutes_unit, seconds_unit);
    } else {
        seconds_unit = addUnit(seconds, "second");
        snprintf(result, MAXMESSAGELEN, "%s", seconds_unit);
    }

    if (hours_unit != NULL) {
        free(hours_unit);
    }
    if (minutes_unit != NULL) {
        free(minutes_unit);
    }
    if (seconds_unit != NULL) {
        free(seconds_unit);
    }

    return result;
}

static bool check_send_notification(tunnel_identity *tnl_id) {
    if (!tnl_id->MfaEnabled || tnl_id->MfaMinTimeout <= 0 || tnl_id->MinTimeoutRemInSvcEvent <=0) {
        return false;
    }
    if (tnl_id->MfaMinTimeoutRem > 0) {
        tnl_id->MfaMinTimeoutRem = get_remaining_timeout((int)tnl_id->MfaMinTimeout, (int)tnl_id->MinTimeoutRemInSvcEvent, tnl_id);
    }
    if (tnl_id->MfaMaxTimeoutRem > 0) {
        tnl_id->MfaMaxTimeoutRem = get_remaining_timeout((int)tnl_id->MfaMaxTimeout, (int)tnl_id->MaxTimeoutRemInSvcEvent, tnl_id);
    }

    if (tnl_id->Notified) {
        // No need to send notification again
        return false;
    }

    if (tnl_id->MfaMinTimeoutRem > 20 * 60) {
        // No services are nearing timeout
        return false;
    } else {
        return true;
    }
}

static notification_message *create_notification_message(tunnel_identity *tnl_id) {
    notification_message *notification = calloc(1, sizeof(struct notification_message_s));
    char *Message = calloc(MAXMESSAGELEN, sizeof(char));
    if (tnl_id->MfaMaxTimeoutRem == 0) {
        snprintf(Message, MAXMESSAGELEN, "All of the services of identity %s have timed out", tnl_id->Name);
        notification->Severity = event_severity_critical;
    } else if (tnl_id->MfaMinTimeoutRem == 0) {
        snprintf(Message, MAXMESSAGELEN, "Some of the services of identity %s have timed out", tnl_id->Name);
        notification->Severity = event_severity_major;
    } else if (tnl_id->MfaMinTimeoutRem <= 20*60) {
        char* message = convert_seconds_to_readable_format((int)tnl_id->MfaMinTimeoutRem);
        snprintf(Message, MAXMESSAGELEN, "Some of the services of identity %s are timing out in %s", tnl_id->Name, message);
        free(message);
        notification->Severity = event_severity_minor;
    } else {
        // do nothing
    }
    notification->Message = Message;

    notification->IdentityName = strdup(tnl_id->Name);
    notification->Identifier = strdup(tnl_id->Identifier);
    uv_timeval64_t now;
    uv_gettimeofday(&now);
    if(tnl_id->MfaLastUpdatedTime) {
        notification->MfaTimeDuration = now.tv_sec - tnl_id->MfaLastUpdatedTime->tv_sec;
    }
    notification->MfaMinimumTimeout = tnl_id->MfaMinTimeoutRem;
    notification->MfaMaximumTimeout = tnl_id->MfaMaxTimeoutRem;

    return notification;
}

static void broadcast_metrics(uv_timer_t *timer) {
    tunnel_metrics_event metrics_event = {0};
    metrics_event.Op = strdup("metrics");
    metrics_event.Identities = get_tunnel_identities_for_metrics();
    tunnel_identity *tnl_id;
    int idx;
    bool active_identities = false;
    if (metrics_event.Identities != NULL) {
        model_map notification_map = {0};
        for(idx = 0; metrics_event.Identities[idx]; idx++) {
            tnl_id = metrics_event.Identities[idx];
            if (tnl_id->Active && tnl_id->Loaded) {
                active_identities = true;

                tunnel_identity_id get_metrics = {
                        .identifier = tnl_id->Identifier,
                };
                size_t json_len;
                tunnel_command tnl_cmd = {
                        .command = TunnelCommand_GetMetrics,
                        .data = tunnel_identity_id_to_json(&get_metrics, MODEL_JSON_COMPACT, &json_len),
                };

                tunnel_command_inline *tnl_cmd_inline = alloc_tunnel_command_inline();
                tnl_cmd_inline->identifier = strdup(tnl_id->Identifier);
                tnl_cmd_inline->command = TunnelCommand_GetMetrics;
                send_tunnel_command_inline(&tnl_cmd, tnl_cmd_inline);
                free_tunnel_command(&tnl_cmd);

                // check timeout
                if (check_send_notification(tnl_id)) {
                    notification_message *message = create_notification_message(tnl_id);
                    if (strlen(message->Message) > 0) {
                        model_map_set(&notification_map, tnl_id->Name, message);
                        tnl_id->Notified = true;
                        ZITI_LOG(INFO, "Notification Message: %s", message->Message);
                    }
                }
            }
        }
        if (model_map_size(&notification_map) > 0) {
            notification_event event = {0};
            event.Op = strdup("notification");
            notification_message_array notification_messages = calloc(model_map_size(&notification_map) + 1, sizeof(notification_message *));
            int notification_idx = 0;
            const char* key;
            notification_message *message;
            MODEL_MAP_FOREACH(key, message, &notification_map) {
                notification_messages[notification_idx++] = message;
            }
            event.Notification = notification_messages;

            send_events_message(&event, (to_json_fn) notification_event_to_json, true);
            event.Notification = NULL;
            free_notification_event(&event);
            model_map_clear(&notification_map, (_free_f) free_notification_message);
            free(notification_messages);
        }
    }

    if (active_identities)
    {
        // do not display the metrics events in the logs as this event will get called every 5 seconds
        send_events_message(&metrics_event, (to_json_fn) tunnel_metrics_event_to_json, false);
    }
    if (metrics_event.Identities) {
        for (idx = 0; metrics_event.Identities[idx]; idx++) {
            free(metrics_event.Identities[idx]);
        }
        free(metrics_event.Identities);
        metrics_event.Identities = NULL;
    }
    free_tunnel_metrics_event(&metrics_event);
}

static void start_metrics_timer(uv_loop_t *ziti_loop) {
    uv_timer_init(ziti_loop, &metrics_timer);
    uv_unref((uv_handle_t *) &metrics_timer);
    uv_timer_start(&metrics_timer, broadcast_metrics, metrics_latency, refresh_metrics);
}

const char *get_filename_ext(const char *filename) {
    const char *dot = strrchr(filename, '.');
    if(!dot || dot == filename) return "";
    return dot + 1;
}

static void load_identities(uv_work_t *wr) {
    if (config_dir != NULL) {
        uv_fs_t fs;
        int rc = uv_fs_scandir(wr->loop, &fs, config_dir, 0, NULL);
        if (rc < 0) {
            ZITI_LOG(ERROR, "failed to scan dir[%s]: %d/%s", config_dir, rc, uv_strerror(rc));
            return;
        }
        ZITI_LOG(TRACE, "scan dir %s, file count: %d", config_dir, rc);

        uv_dirent_t file;
        while (uv_fs_scandir_next(&fs, &file) == 0) {
            ZITI_LOG(TRACE, "processing file: %s %d", file.name, rc);
            if(file.type != UV_DIRENT_FILE) {
                ZITI_LOG(DEBUG, "skipping file in config dir as it's not the proper type. type: %d. file: %s", file.type, file.name);
                continue;
            }

            if (strcasecmp(file.name, get_config_file_name(NULL)) == 0) {
                ZITI_LOG(DEBUG, "skipping the configuration file: %s", file.name);
                continue;
            } else if(strcasecmp(file.name, get_backup_config_file_name(NULL)) == 0 ) {
                ZITI_LOG(DEBUG, "skipping the backup configuration file: %s", file.name);
                continue;
            }

            const char* ext = get_filename_ext(file.name);

            // ignore back up files
            if (strcasecmp(ext, ".bak") == 0 || strcasecmp(ext, ".original") == 0 || strcasecmp(ext, "json") != 0) {
                ZITI_LOG(DEBUG, "skipping backup file: %s", file.name);
                continue;
            }

            ZITI_LOG(INFO, "loading identity file: %s", file.name);
            if (file.type == UV_DIRENT_FILE) {
                struct cfg_instance_s *inst = calloc(1, sizeof(struct cfg_instance_s));
                inst->cfg = malloc(MAXPATHLEN);
                snprintf(inst->cfg, MAXPATHLEN, "%s%c%s", config_dir, PATH_SEP, file.name);
                create_or_get_tunnel_identity(inst->cfg, file.name);
                LIST_INSERT_HEAD(&load_list, inst, _next);
            }
        }
    }
}

static void load_id_cb(const tunnel_result *res, void *ctx) {
    struct cfg_instance_s *inst = ctx;

    if (res->success) {
        ZITI_LOG(INFO, "identity[%s] loaded", inst->cfg);
    } else {
        ZITI_LOG(ERROR, "identity[%s] failed to load: %s", inst->cfg, res->error);
    }
}

static void load_identities_complete(uv_work_t * wr, int status) {
    bool identity_loaded = false;
    while(!LIST_EMPTY(&load_list)) {
        struct cfg_instance_s *inst = LIST_FIRST(&load_list);
        LIST_REMOVE(inst, _next);

        if (config_dir == NULL) {
            create_or_get_tunnel_identity(inst->cfg, inst->cfg);
        }

        tunnel_identity *id = find_tunnel_identity(inst->cfg);
        if(id != NULL) {
            CMD_CTRL->load_identity(NULL, inst->cfg, !id->Active, get_api_page_size(), load_id_cb, inst);
        } else {
            ZITI_LOG(WARN, "identity not found? %s", inst->cfg);
        }

        identity_loaded = true;
    }
    if (identity_loaded) {
        start_metrics_timer(wr->loop);
    }

    // should be the last line in this function as it calls the mutex/lock
    save_tunnel_status_to_file();
}

static void on_event(const base_event *ev) {
    tunnel_identity *id = find_tunnel_identity(ev->identifier);
    switch (ev->event_type) {
        case TunnelEvent_ContextEvent: {
            const ziti_ctx_event *zev = (ziti_ctx_event *) ev;
            ZITI_LOG(INFO, "ztx[%s] context event : status is %s", ev->identifier, zev->status);
            if (id == NULL) {
                break;
            }

            identity_event id_event = {0};
            id_event.Op = strdup("identity");
            id_event.Action = strdup(event_name(event_added));
            id_event.Id = id;
            if (id_event.Id->FingerPrint) {
                id_event.Fingerprint = strdup(id_event.Id->FingerPrint);
            }
            id_event.Id->Loaded = true;
            id_event.Id->NeedsExtAuth = false;

            action_event controller_event = {0};
            controller_event.Op = strdup("controller");
            controller_event.Identifier = strdup(ev->identifier);
            if (id_event.Id->FingerPrint) {
                controller_event.Fingerprint = strdup(id_event.Id->FingerPrint);
            }

            if (zev->code == ZITI_OK) {
                if (zev->name) {
                    if (id_event.Id->Name != NULL && strcmp(id_event.Id->Name, zev->name) != 0) {
                        free((char*)id_event.Id->Name);
                        id_event.Id->Name = strdup(zev->name);
                    } else if (id_event.Id->Name == NULL) {
                        id_event.Id->Name = strdup(zev->name);
                    }
                }
                if (zev->version) {
                    if (id_event.Id->ControllerVersion != NULL && strcmp(id_event.Id->ControllerVersion, zev->version) != 0) {
                        free((char*)id_event.Id->ControllerVersion);
                        id_event.Id->ControllerVersion = strdup(zev->version);
                    } else if (id_event.Id->ControllerVersion == NULL) {
                        id_event.Id->ControllerVersion = strdup(zev->version);
                    }
                }
                if (zev->controller) {
                    if (id_event.Id->Config != NULL && id_event.Id->Config->ZtAPI != NULL && strcmp(id_event.Id->Config->ZtAPI, zev->controller) != 0) {
                        free((char*)id_event.Id->Config->ZtAPI);
                        id_event.Id->Config->ZtAPI = strdup(zev->controller);
                    } else if (id_event.Id->Config == NULL) {
                        id_event.Id->Config = calloc(1, sizeof(tunnel_config));
                        id_event.Id->Config->ZtAPI = strdup(zev->controller);
                    } else if (id_event.Id->Config->ZtAPI == NULL) {
                        id_event.Id->Config->ZtAPI = strdup(zev->controller);
                    }
                }
                controller_event.Action = strdup(event_name(event_connected));
                ZITI_LOG(DEBUG, "ztx[%s] controller connected", ev->identifier);
            } else {
                controller_event.Action = strdup(event_name(event_disconnected));
                ZITI_LOG(ERROR, "ztx[%s] failed to connect to controller due to %s", ev->identifier, zev->status);
            }

            send_events_message(&id_event, (to_json_fn) identity_event_to_json, true);
            id_event.Id = NULL;
            free_identity_event(&id_event);

            send_events_message(&controller_event, (to_json_fn) action_event_to_json, true);
            free_action_event(&controller_event);
            break;
        }

        case TunnelEvent_ServiceEvent: {
            const service_event *svc_ev = (service_event *) ev;
            ZITI_LOG(VERBOSE, "=============== ztx[%s] service event ===============", ev->identifier);
            if (id == NULL) {
                break;
            }

            services_event svc_event = {
                .Op = strdup("bulkservice"),
                .Action = strdup(event_name(event_updated)),
                .Identifier = strdup(ev->identifier)
            };

            if (id->FingerPrint) {
                svc_event.Fingerprint = strdup(id->FingerPrint);
            }
            ziti_service **zs;
#if _WIN32
            model_map hostnamesToAdd = {0};
            model_map hostnamesToEdit = {0};
            model_map hostnamesToRemove = {0};
#endif
            if (svc_ev->removed_services != NULL) {
                int svc_array_length = 0;
                for (zs = svc_ev->removed_services; *zs != NULL; zs++) {
                    svc_array_length++;
                }
                svc_event.RemovedServices = calloc(svc_array_length + 1, sizeof(struct tunnel_service_s));
                for (int svc_idx = 0; svc_ev->removed_services[svc_idx]; svc_idx++) {
                    tunnel_service *svc = find_tunnel_service(id, svc_ev->removed_services[svc_idx]->id);
                    if (svc == NULL) {
                        svc = get_tunnel_service(id, svc_ev->removed_services[svc_idx]);
                    }
                    ZITI_LOG(INFO, "=============== service event (removed) - %s:%s ===============", svc->Name, svc->Id);
#if _WIN32
                    if (svc->Addresses != NULL) {
                        for (int i = 0; svc->Addresses[i]; i++) {
                            tunnel_address *addr = svc->Addresses[i];
                            if (addr->IsHost && model_map_get(&hostnamesToRemove, addr->HostName) == NULL) {
                                model_map_set(&hostnamesToRemove, addr->HostName, "TRUE");
                            }
                        }
                    }
#endif
                    svc_event.RemovedServices[svc_idx] = svc;
                }
            }

            if (svc_ev->added_services != NULL) {
                int svc_array_length = 0;
                for (zs = svc_ev->added_services; *zs != NULL; zs++) {
                    svc_array_length++;
                }
                svc_event.AddedServices = calloc(svc_array_length + 1, sizeof(tunnel_service *));
                for (int svc_idx = 0; svc_ev->added_services[svc_idx]; svc_idx++) {
                    tunnel_service *svc = get_tunnel_service(id, svc_ev->added_services[svc_idx]);
                    svc_event.AddedServices[svc_idx] = svc;
                    ZITI_LOG(INFO, "=============== service event (added) - %s:%s ===============", svc->Name, svc->Id);
#if _WIN32
                    if (svc->Addresses != NULL) {
                        for (int i = 0; svc->Addresses[i]; i++) {
                            tunnel_address *addr = svc->Addresses[i];
                            bool has_dial = ziti_service_has_permission(svc_ev->added_services[svc_idx], ziti_session_type_Dial);
                            if (addr->IsHost && model_map_get(&hostnamesToAdd, addr->HostName) == NULL && has_dial) {
                                if (model_map_get(&hostnamesToRemove, addr->HostName) != NULL) {
                                    model_map_set(&hostnamesToEdit, addr->HostName, "TRUE");
                                } else {
                                    model_map_set(&hostnamesToAdd, addr->HostName, "TRUE");
                                }
                            }
                        }
                    }
#endif
                }
            }


#if _WIN32
            // remove the hostnames from hostnamesToRemove, if they are present in hostnamesToEdit
            if (model_map_size(&hostnamesToEdit) > 0) {
                model_map_iter it = model_map_iterator(&hostnamesToRemove);
                while (it != NULL) {
                    const char *key = model_map_it_key(it);
                    if (model_map_get(&hostnamesToEdit, key) != NULL) {
                        it = model_map_it_remove(it);
                    } else {
                        it = model_map_it_next(it);
                    }
                }
            }
            
            if (id->Active && model_map_size(&hostnamesToEdit) > 0 && !is_host_only()) {
                remove_and_add_nrpt_rules(global_loop_ref, &hostnamesToEdit, get_dns_ip());
            }
            if (id->Active && model_map_size(&hostnamesToAdd) > 0 && !is_host_only()) {
                add_nrpt_rules(global_loop_ref, &hostnamesToAdd, get_dns_ip());
            }
            if (model_map_size(&hostnamesToRemove) > 0 && !is_host_only()) {
                remove_nrpt_rules(global_loop_ref, &hostnamesToRemove);
            }

#endif

            if (svc_ev->removed_services != NULL || svc_ev->added_services != NULL) {
                add_or_remove_services_from_tunnel(id, svc_event.AddedServices, svc_event.RemovedServices);
            }

            send_events_message(&svc_event, (to_json_fn) services_event_to_json, true);
            if (svc_event.AddedServices != NULL) {
                tunnel_service **tnl_svc_arr = svc_event.AddedServices;
                *tnl_svc_arr = NULL;
                free(tnl_svc_arr);
                svc_event.AddedServices = NULL;
            }
            free_services_event(&svc_event);

            identity_event id_event = {
                    .Op = strdup("identity"),
                    .Action = strdup(event_name(event_updated)),
                    .Id = create_or_get_tunnel_identity(ev->identifier, NULL),
            };
            if (id_event.Id->FingerPrint) {
                id_event.Fingerprint = strdup(id_event.Id->FingerPrint);
            }
            send_events_message(&id_event, (to_json_fn) identity_event_to_json, true);
            id_event.Id = NULL;
            free_identity_event(&id_event);
            break;
        }

        case TunnelEvent_MFAEvent: {
            const mfa_event *mfa_ev = (mfa_event *) ev;
            ZITI_LOG(INFO, "ztx[%s] is requesting MFA code. Identity needs MFA", ev->identifier);
            if (id == NULL) {
                break;
            }
            set_mfa_status(ev->identifier, id->MfaEnabled, true);
            send_tunnel_status("status");
            mfa_status_event mfa_sts_event = {
                    .Op = strdup("mfa"),
                    .Action = strdup(mfa_ev->operation),
                    .Identifier = strdup(mfa_ev->identifier),
                    .Successful = false
            };

            if (id->FingerPrint) {
                mfa_sts_event.Fingerprint = strdup(id->FingerPrint);
            }

            send_events_message(&mfa_sts_event, (to_json_fn) mfa_status_event_to_json, true);
            free_mfa_status_event(&mfa_sts_event);
            break;
        }

        case TunnelEvent_MFAStatusEvent:{
            const mfa_event *mfa_ev = (mfa_event *) ev;
            ZITI_LOG(INFO, "ztx[%s] MFA Status code : %d", ev->identifier, (int)mfa_ev->code);

            mfa_status_event mfa_sts_event = {
                .Op = strdup("mfa"),
                .Action = strdup(mfa_ev->operation),
                .Identifier = strdup(mfa_ev->identifier)
            };

            if (mfa_ev->code == ZITI_OK) {
                switch (mfa_ev->operation_type) {
                    case mfa_status_mfa_auth_status:
                    case mfa_status_enrollment_verification:
                        set_mfa_status(ev->identifier, true, false);
                        update_mfa_time(ev->identifier);

                        identity_event id_event = {
                                .Op = strdup("identity"),
                                .Action = strdup(event_name(event_updated)),
                                .Id = create_or_get_tunnel_identity(ev->identifier, NULL),
                        };
                        if (id_event.Id->FingerPrint) {
                            id_event.Fingerprint = strdup(id_event.Id->FingerPrint);
                        }
                        send_events_message(&id_event, (to_json_fn) identity_event_to_json, true);
                        id_event.Id = NULL;
                        free_identity_event(&id_event);
                        save_tunnel_status_to_file(); // persist the mfa change
                        break;
                    case mfa_status_enrollment_remove:
                        set_mfa_status(ev->identifier, false, false);
                        save_tunnel_status_to_file(); // persist the mfa change
                        break;
                    case mfa_status_enrollment_challenge:
                        mfa_sts_event.RecoveryCodes = mfa_ev->recovery_codes;
                        mfa_sts_event.ProvisioningUrl = strdup(mfa_ev->provisioning_url);
                        break;
                    default:
                        ZITI_LOG(WARN, "ztx[%s] MFA unknown status : %d", ev->identifier, mfa_ev->operation_type);
                }

                mfa_sts_event.Successful = true;
            } else {
                mfa_sts_event.Successful = false;
                mfa_sts_event.Error = strdup(mfa_ev->status);
            }

            if (id == NULL) {
                id = create_or_get_tunnel_identity(ev->identifier, NULL);
            }
            if (id->FingerPrint) {
                mfa_sts_event.Fingerprint = strdup(id->FingerPrint);
            }

            send_events_message(&mfa_sts_event, (to_json_fn) mfa_status_event_to_json, true);

            mfa_sts_event.RecoveryCodes = NULL;
            free_mfa_status_event(&mfa_sts_event);
            free_mfa_event((mfa_event *) mfa_ev);
            break;
        }

        case TunnelEvent_APIEvent: {
            const api_event *api_ev = (api_event *) ev;
            ZITI_LOG(INFO, "ztx[%s] API Event with controller address : %s", api_ev->identifier, api_ev->new_ctrl_address);
            if (id == NULL) {
                break;
            }

            identity_event id_event = {0};
            id_event.Op = strdup("identity");
            id_event.Action = strdup(event_name(event_updated));
            id_event.Id = id;
            if (id_event.Id->FingerPrint) {
                id_event.Fingerprint = strdup(id_event.Id->FingerPrint);
            }
            id_event.Id->Loaded = true;
            bool updated = false;
            if (api_ev->new_ctrl_address) {
                if (id_event.Id->Config == NULL) {
                    id_event.Id->Config = calloc(1, sizeof(tunnel_config));
                    id_event.Id->Config->ZtAPI = strdup(api_ev->new_ctrl_address);
                    updated = true;
                } else if (id_event.Id->Config->ZtAPI != NULL && strcmp(id_event.Id->Config->ZtAPI, api_ev->new_ctrl_address) != 0) {
                    free((char*)id_event.Id->Config->ZtAPI);
                    id_event.Id->Config->ZtAPI = strdup(api_ev->new_ctrl_address);
                    updated = true;
                }
            }
            if (updated) {
                send_events_message(&id_event, (to_json_fn) identity_event_to_json, true);
            }
            id_event.Id = NULL;
            free_identity_event(&id_event);
            break;
        }
        case TunnelEvent_ExtJWTEvent:
            if (id != NULL){
                const ext_signer_event *ese = (const ext_signer_event *) ev;
                id->NeedsExtAuth = true;
                ZITI_LOG(INFO, "ztx[%s] ext auth: %s", id->Identifier, ese->status);
                identity_event id_event = {0};
                id_event.Op = "identity";
                id_event.Action = (char*)event_name(event_needs_ext_login);
                id_event.Id = id;
                if (id_event.Id->FingerPrint) {
                    id_event.Fingerprint = id_event.Id->FingerPrint;
                }
                send_events_message(&id_event, (to_json_fn) identity_event_to_json, true);
            }
            break;
        case TunnelEvent_Unknown:
        default:
            ZITI_LOG(WARN, "unhandled event received: %d", ev->event_type);
            break;
    }
}

static char* normalize_host(char* hostname) {
    size_t len = strlen(hostname);
    char* hostname_new = calloc(len+2, sizeof(char));
    // add . in the beginning of the hostname
    if (hostname[len-1] == '.') {
        // remove the . from the end of the hostname
        snprintf(hostname_new, len * sizeof(char), ".%s", hostname);
    } else {
        snprintf(hostname_new, len + 2, ".%s", hostname);
    }
    return hostname_new;
}

static int run_tunnel(uv_loop_t *ziti_loop, uint32_t tun_ip, uint32_t dns_ip, const char *ip_range, const char *dns_upstream) {
    netif_driver tun;
    char tun_error[64];

    // remove the host bits from the dns cidr so added routes are valid
    char dns_subnet[64];
    ziti_address dns_subnet_zaddr;
    ziti_address_from_string(&dns_subnet_zaddr, ip_range);
    struct in_addr *dns_subnet_in = (struct in_addr *)&dns_subnet_zaddr.addr.cidr.ip;
    uint32_t dns_subnet_u32 = ntohl(dns_subnet_in->s_addr) & (0xFFFFFFFFUL << (32 - dns_subnet_zaddr.addr.cidr.bits)) & 0xFFFFFFFFUL;
    ip_addr_t dns_ip4_addr = IPADDR4_INIT(htonl(dns_subnet_u32));
    snprintf(dns_subnet, sizeof(dns_subnet), "%s/%d", ipaddr_ntoa(&dns_ip4_addr), dns_subnet_zaddr.addr.cidr.bits);
#if __APPLE__ && __MACH__
    tun = utun_open(tun_error, sizeof(tun_error), ip_range);
#elif __linux__
    tun = tun_open(ziti_loop, tun_ip, dns_ip, dns_subnet, tun_error, sizeof(tun_error),
        &(struct netif_options){ .use_rt_main  = use_rt_main() });
#elif _WIN32
    tun = tun_open(ziti_loop, tun_ip, dns_subnet, tun_error, sizeof(tun_error));
#else
#error "ziti-edge-tunnel is not supported on this system"
#endif

    if (tun == NULL) {
        ZITI_LOG(ERROR, "failed to open network interface: %s", tun_error);
        return 1;
    }

#if _WIN32
    bool nrpt_effective = is_nrpt_policies_effective(get_dns_ip());
    if (!nrpt_effective || get_add_dns_flag()) {
        if (get_add_dns_flag()) {
            ZITI_LOG(INFO, "DNS is enabled for the TUN interface, because apply Dns flag in the config file is true");
        }
        if (!nrpt_effective && !get_add_dns_flag()) {
            ZITI_LOG(INFO, "DNS is enabled for the TUN interface, because Ziti policies test result in this client is false");
        }
        set_dns(tun->handle, dns_ip);
        ZITI_LOG(INFO, "Setting interface metric to 5");
        update_interface_metric(ziti_loop, get_tun_name(tun->handle), 5);
    } else {
        ZITI_LOG(INFO, "Setting interface metric to 255");
        update_interface_metric(ziti_loop, get_tun_name(tun->handle), 255);
    }
#endif

    tunneler = initialize_tunneler(tun, ziti_loop);

    ip_addr_t dns_ip4 = IPADDR4_INIT(dns_ip);
    ziti_dns_setup(tunneler, ipaddr_ntoa(&dns_ip4), ip_range);
    if (dns_upstream) {
        tunnel_upstream_dns upstream = {
                .host = dns_upstream
        };
        tunnel_upstream_dns *a[] = { &upstream, NULL};
        ziti_dns_set_upstream(ziti_loop, a);
    }
    run_tunneler_loop(ziti_loop);
    if (tun->close) {
        tun->close(tun->handle);
    }
    return 0;
}

static int run_tunnel_host_mode(uv_loop_t *ziti_loop) {
    tunneler = initialize_tunneler(NULL, ziti_loop);
    run_tunneler_loop(ziti_loop);
    return 0;
}

static int make_socket_path(uv_loop_t *loop) {

#if defined(SOCKET_PATH)
#define ZITI_GRNAME "ziti"
    uv_fs_t req;
    int rc;

    // set effective group to "ziti"
    struct group *ziti_grp = getgrnam(ZITI_GRNAME);
    if (!ziti_grp) {
        ZITI_LOG(WARN, "local '%s' group not found.", ZITI_GRNAME);
        ZITI_LOG(WARN, "please create the '%s' group by running these commands:", ZITI_GRNAME);
#if __linux__
        ZITI_LOG(WARN, "sudo groupadd --system %s", ZITI_GRNAME);
        ZITI_LOG(WARN, "users can then be added to the '%s' group with:", ZITI_GRNAME);
        ZITI_LOG(WARN, "sudo usermod --append --groups %s <USER>", ZITI_GRNAME);
#elif (__APPLE__ && __MACH__)
        ZITI_LOG(WARN, "sudo dseditgroup -o create %s", ZITI_GRNAME);
        ZITI_LOG(WARN, "users can then be added to the '%s' group with:", ZITI_GRNAME);
        ZITI_LOG(WARN, "sudo dscl . -append /groups/%s GroupMembership <USER>", ZITI_GRNAME);
#endif
        return -1;
    }

    ZITI_LOG(DEBUG, "local group '%s' exists, gid=%d", ZITI_GRNAME, ziti_grp->gr_gid);
    if (setgid(ziti_grp->gr_gid) == 0) {
        ZITI_LOG(INFO, "effective group set to '%s' (gid=%d)", ziti_grp->gr_name, ziti_grp->gr_gid);
    } else {
        ZITI_LOG(WARN, "failed setting effective group to 'ziti': %s (errno=%d)", strerror(errno), errno);
        return -1;
    }

    rc = uv_fs_mkdir(loop, &req, SOCKET_PATH, S_IRWXU|S_IRGRP|S_IXGRP, NULL);
    uv_fs_req_cleanup(&req);

    if (rc == 0) {
        ZITI_LOG(DEBUG, "created socket directory %s", SOCKET_PATH);
        return 0;
    } else if (rc != UV_EEXIST) {
        ZITI_LOG(WARN, "Cannot create socket directory '%s': %s (%d)", SOCKET_PATH, uv_strerror(rc), rc);
        return -1;
    }

    // the directory already existed, check/set permissions as needed */
    bool perms_ok = true;
    rc = uv_fs_lstat(loop, &req, SOCKET_PATH, NULL);
    if (rc == 0) {
        // ensure SOCKET_PATH is a directory.
        if (!S_ISDIR(req.statbuf.st_mode)) {
            ZITI_LOG(WARN, "IPC socket path '%s' is not a directory", SOCKET_PATH);
            perms_ok = false;
            goto done;
        }
        // ensure it has correct permissions
        if (req.statbuf.st_mode & (S_IRWXO | S_IWGRP)) {
            if (chmod(SOCKET_PATH, S_IRWXU|S_IRGRP|S_IXGRP) == 0) {
                ZITI_LOG(DEBUG, "successfully set permissions of %s to 0%o", SOCKET_PATH, S_IRWXU|S_IRGRP|S_IXGRP);
            } else {
                ZITI_LOG(WARN, "failed to set permissions of %s to 0%o: %s (%d)", SOCKET_PATH, S_IRWXU|S_IRGRP|S_IXGRP, strerror(errno), errno);
                perms_ok = false;
                goto done;
            }
        }
        // ensure it has correct owner/group
        if (geteuid() != req.statbuf.st_uid || req.statbuf.st_gid != ziti_grp->gr_gid) {
            ZITI_LOG(DEBUG, "attempting to set ownership of IPC socket directory %s to %d:%d", SOCKET_PATH,
                     geteuid(), ziti_grp->gr_gid);
            if (chown(SOCKET_PATH, geteuid(), ziti_grp->gr_gid) == 0) {
                ZITI_LOG(DEBUG, "successfully set ownership of %s to %d:%d", SOCKET_PATH, geteuid(), ziti_grp->gr_gid);
            } else {
                ZITI_LOG(WARN, "failed to set ownership of %s to %d:%d: %s (errno=%d)", SOCKET_PATH, geteuid(),
                         ziti_grp->gr_gid, strerror(errno), errno);
                perms_ok = false;
                goto done;
            }
        }
    } else {
        ZITI_LOG(WARN, "lstat(%s) failed: %s (%d)", SOCKET_PATH, uv_strerror(rc), rc);
        perms_ok = false;
    }

    done:
    uv_fs_req_cleanup(&req);
    return perms_ok ? 0 : -1;

#endif /* defined(SOCKET_PATH) */

    return 0;
}

#if __linux__ || __APPLE__
static void on_exit_signal(uv_signal_t *s, int sig) {
    ZITI_LOG(WARN, "received signal: %s", strsignal(sig));
    exit(1);
}
#endif

static void run_tunneler_loop(uv_loop_t* ziti_loop) {

#if _WIN32
    // set the service to running state
    scm_running_event();
#endif

#if __linux__ || __APPLE__
#define handle_sig(n, f) \
    uv_signal_t sig_##n;                     \
    uv_signal_init(ziti_loop, &sig_##n); \
    uv_signal_start(&sig_##n, f, n); \
    uv_unref((uv_handle_t *) &sig_##n)

    handle_sig(SIGINT, on_exit_signal);
    handle_sig(SIGTERM, on_exit_signal);
    handle_sig(SIGABRT, on_exit_signal);
    handle_sig(SIGSEGV, on_exit_signal);
    handle_sig(SIGQUIT, on_exit_signal);

#undef handle_sig

#endif

    CMD_CTRL = ziti_tunnel_init_cmd(ziti_loop, tunneler, on_event);

    if (config_dir != NULL) {
        ZITI_LOG(INFO, "Loading identity files from %s", config_dir);
    }

    uv_work_t *loader = calloc(1, sizeof(uv_work_t));
    uv_queue_work(ziti_loop, loader, load_identities, load_identities_complete);

    int rc0 = 0, rc1;
    rc0 = rc1 = make_socket_path(ziti_loop);
    if (rc0 == 0) {
        rc0 = start_cmd_socket(ziti_loop);
        rc1 = start_event_socket(ziti_loop);
    }

    if (rc0 < 0 || rc1 < 0) {
      ZITI_LOG(WARN, "One or more socket servers did not properly start.");
    }

#if _WIN32
    ipc_cmd_ctx = calloc(1, sizeof(struct ipc_cmd_ctx_s));
    STAILQ_INIT(&ipc_cmd_ctx->ipc_cmd_queue);
#endif

    if (uv_run(ziti_loop, UV_RUN_DEFAULT) != 0) {
        if (started_by_scm) {
            ZITI_LOG(INFO, "The event loop is stopped, normal shutdown complete");
        } else if (tunnel_interrupted) {
            ZITI_LOG(INFO, "============================ tunnel interrupted ==================================");
        } else {
            ZITI_LOG(ERROR, "failed to run event loop");
            exit(1);
        }
    }

    free(tunneler);
}

static tunneler_context initialize_tunneler(netif_driver tun, uv_loop_t* ziti_loop) {

    tunneler_sdk_options tunneler_opts = {
            .netif_driver = tun,
            .ziti_dial = ziti_sdk_c_dial,
            .ziti_close = ziti_sdk_c_close,
            .ziti_close_write = ziti_sdk_c_close_write,
            .ziti_write = ziti_sdk_c_write,
            .ziti_host = ziti_sdk_c_host

    };

    if (is_host_only()) {
        return ziti_tunneler_init_host_only(&tunneler_opts, ziti_loop);
    } else {
        return ziti_tunneler_init(&tunneler_opts, ziti_loop);
    }
}

#define COMMAND_LINE_IMPLEMENTATION
#include <commandline.h>
#include <getopt.h>

#define CHECK_COMMAND_ERRORS(errors) \
    do { \
        if (errors > 0) { \
            commandline_help(stderr); \
            exit(EXIT_FAILURE); \
        } \
    } while (0)


static CommandLine main_cmd;
static void usage(int argc, char *argv[]) {
    if (argc == 0) {
        commandline_print_usage(&main_cmd, stdout);
        return;
    }

    if (strcmp(argv[0], "help") == 0) {
        printf("seriously? you need help\n");
        return;
    }
    char *help_args[] = {
            "ziti-edge-tunnel",
            argv[0],
            "-h"
    };
    commandline_run(&main_cmd, 3, help_args);
}

#define ZET__OPTVAL_PREFER_RT_MAIN 256

static struct option run_options[] = {
        { "identity", required_argument, NULL, 'i' },
        { "identity-dir", required_argument, NULL, 'I'},
        { "verbose", required_argument, NULL, 'v'},
        { "refresh", required_argument, NULL, 'r'},
        { "dns-ip-range", required_argument, NULL, 'd'},
        { "dns-upstream", required_argument, NULL, 'u'},
        { "proxy", required_argument, NULL, 'x' },
        { "use-main-routing-table", no_argument, NULL, ZET__OPTVAL_PREFER_RT_MAIN},
};

static struct option run_host_options[] = {
        { "identity", required_argument, NULL, 'i' },
        { "identity-dir", required_argument, NULL, 'I'},
        { "verbose", required_argument, NULL, 'v'},
        { "refresh", required_argument, NULL, 'r'},
        { "proxy", required_argument, NULL, 'x' },
        { "use-main-routing-table", no_argument, NULL, ZET__OPTVAL_PREFER_RT_MAIN},
};

#ifndef DEFAULT_DNS_CIDR
#define DEFAULT_DNS_CIDR "100.64.0.1/10"
#endif
static const char* dns_upstream = NULL;
static bool host_only = false;

static int opt_prefer_rt_main = -1;

#include "tlsuv/http.h"

static int init_proxy_connector(const char *url) {
    if (url == NULL) url = getenv("HTTP_PROXY");
    if (url == NULL) url = getenv("http_proxy");
    if (url == NULL) {
        ZITI_LOG(DEBUG, "proxy_url not set");
        return 0;
    }

    struct tlsuv_url_s proxy_url;
    int r = tlsuv_parse_url(&proxy_url, url);
    if (r != 0) {
        ZITI_LOG(ERROR, "failed to parse '%s' as 'type://[username[:password]@]hostname:port'", url);
        return -1;
    }

    // assume http if no protocol was specified
    if (proxy_url.scheme == NULL) {
        proxy_url.scheme = "http";
        proxy_url.scheme_len = strlen(proxy_url.scheme);
    }

    if (strncmp(proxy_url.scheme, "http", proxy_url.scheme_len) != 0) {
        ZITI_LOG(ERROR, "proxy type '%.*s' is not supported. 'http' is currently the only supported type",
                 (int)proxy_url.scheme_len, proxy_url.scheme);
        return -1;
    }

    char host[128], port[6];
    snprintf(host, sizeof(host), "%.*s", (int)proxy_url.hostname_len, proxy_url.hostname);
    snprintf(port, sizeof(port), "%d", proxy_url.port);
    tlsuv_connector_t *proxy = tlsuv_new_proxy_connector(tlsuv_PROXY_HTTP, host, port);
    if (proxy_url.username) {
        char user[128], passwd[128];
        snprintf(user, sizeof(user), "%.*s", (int)proxy_url.username_len, proxy_url.username);
        snprintf(passwd, sizeof(passwd), "%.*s", (int)proxy_url.password_len, proxy_url.password);
        proxy->set_auth(proxy, tlsuv_PROXY_BASIC, user, passwd);
    }
    ZITI_LOG(INFO, "connecting to OpenZiti controller and edge routers through proxy '%s:%s'", host, port);
    tlsuv_set_global_connector(proxy);

    return 0;
}

static int run_opts(int argc, char *argv[]) {
    int c, option_index, errors = 0;
    optind = 0;
    bool identity_provided = false;

    while ((c = getopt_long(argc, argv, "i:I:v:r:d:u:x:",
                            run_options, &option_index)) != -1) {
        switch (c) {
            case 'i': {
                struct cfg_instance_s *inst = calloc(1, sizeof(struct cfg_instance_s));
                inst->cfg = strdup(optarg);
                LIST_INSERT_HEAD(&load_list, inst, _next);
                identity_provided = true;
                break;
            }
            case 'I':
                config_dir = optarg;
                identity_provided = true;
                break;
            case 'v':
                configured_log_level = optarg;
                break;
            case 'r': {
                unsigned long interval = strtoul(optarg, NULL, 10);
                ziti_set_refresh_interval(interval);
                break;
            }
            case 'd': // ip range
                configured_cidr = optarg;
                break;
            case 'u':
                dns_upstream = optarg;
                break;
            case 'x':
                configured_proxy = optarg;
                break;
            case ZET__OPTVAL_PREFER_RT_MAIN:
                opt_prefer_rt_main = 1;
                break;
            default: {
                fprintf(stderr, "Unknown option '%c'\n", c);
                errors++;
                break;
            }
        }
    }

    CHECK_COMMAND_ERRORS(errors);

    fprintf(stderr, "About to run tunnel service... %s\n", main_cmd.name);
    ziti_set_app_info(main_cmd.name, ziti_tunneler_version());

    return optind;
}

static int run_host_opts(int argc, char *argv[]) {
    int c, option_index, errors = 0;
    optind = 0;
    bool identity_provided = false;

    while ((c = getopt_long(argc, argv, "i:I:v:r:x:",
                            run_host_options, &option_index)) != -1) {
        switch (c) {
            case 'i': {
                struct cfg_instance_s *inst = calloc(1, sizeof(struct cfg_instance_s));
                inst->cfg = strdup(optarg);
                LIST_INSERT_HEAD(&load_list, inst, _next);
                identity_provided = true;
                break;
            }
            case 'I':
                config_dir = optarg;
                identity_provided = true;
                break;
            case 'v':
                configured_log_level = optarg;
                break;
            case 'r': {
                unsigned long interval = strtoul(optarg, NULL, 10);
                ziti_set_refresh_interval(interval);
                break;
            }
            case 'x':
                configured_proxy = optarg;
                break;
            case ZET__OPTVAL_PREFER_RT_MAIN:
                opt_prefer_rt_main = 1;
                break;
            default: {
                fprintf(stderr, "Unknown option '%c'\n", c);
                errors++;
                break;
            }
        }
    }

    if (!identity_provided) {
        errors++;
    }

    CHECK_COMMAND_ERRORS(errors);

    fprintf(stderr, "About to run tunnel service that hosts services... %s\n", main_cmd.name);
    ziti_set_app_info(main_cmd.name, ziti_tunneler_version());

    host_only = true;
    return optind;
}

void dns_set_miss_status(int status) {
    dns_miss_status = status;
}

static int dns_fallback(const char *name, void *ctx, struct in_addr* addr) {
    return dns_miss_status;
}

#if _WIN32
static void interrupt_handler(int sig) {
    ZITI_LOG(WARN,"Received signal to interrupt");
    tunnel_interrupted = true;
    ziti_tunnel_async_send(tunneler, scm_service_stop_event, "interrupted");
}
#endif

static void run(int argc, char *argv[]) {
    uv_cond_init(&stop_cond);
    uv_mutex_init(&stop_mutex);

    initialize_instance_config();

    //set log level in precedence: command line flag (-v/--verbose) -> env var (ZITI_LOG) -> config file
    int log_level = get_log_level(configured_log_level);
    log_writer log_fn = NULL;

#if _WIN32
    // initialize log function here. level will be set further down
    log_init(global_loop_ref);
    log_fn = ziti_log_writer;
    remove_all_nrpt_rules();

    signal(SIGINT, interrupt_handler);
#endif

    ziti_log_init(global_loop_ref, log_level, log_fn);

    // generate tunnel status instance and save active state and start time
    if (config_dir != NULL) {
        set_identifier_path(config_dir);
        load_tunnel_status_from_file(global_loop_ref);
    }

    uint32_t tun_ip;
    uint32_t dns_ip;

    if (!is_host_only()) {
        if (configured_cidr == NULL) {
            //allow the -d flag to override anything in the config
            char *ip_range_temp = get_ip_range_from_config();
            if (ip_range_temp != NULL) {
                configured_cidr = ip_range_temp;
            } else {
                configured_cidr = strdup(DEFAULT_DNS_CIDR);
            }
        }

        uint32_t ip[4];
        int bits;
        int rc = sscanf(configured_cidr, "%d.%d.%d.%d/%d", &ip[0], &ip[1], &ip[2], &ip[3], &bits);
        if (rc != 5) {
            ZITI_LOG(ERROR, "Invalid IP range specification: n.n.n.n/m format is expected");
            exit(EXIT_FAILURE);
        }

        uint32_t mask = 0;
        for (int i = 0; i < 4; i++) {
            mask <<= 8U;
            mask |= (ip[i] & 0xFFU);
        }

        tun_ip = htonl(mask);
        dns_ip = htonl(mask + 1);

        // set ip info into instance
        set_ip_info(dns_ip, tun_ip, bits);
    }
#if __unix__ || __unix
    // prevent termination when running under valgrind
    // client forcefully closing connection results in SIGPIPE
    // which causes valgrind to freak out
    signal(SIGPIPE, SIG_IGN);
#endif

    // set the service version in instance
    set_service_version();

#if _WIN32
    uv_timeval64_t dump_time;
    uv_gettimeofday(&dump_time);
    char time_str[32];
    struct tm* start_tm = gmtime(&dump_time.tv_sec);
    strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%S", start_tm);

    start_tm = localtime(&dump_time.tv_sec);
    char time_val[32];
    strftime(time_val, sizeof(time_val), "%a %b %d %Y, %X %p", start_tm);
    ZITI_LOG(INFO,"============================ service begins ================================");
    ZITI_LOG(INFO,"Logger initialization");
    ZITI_LOG(INFO,"	- initialized at   : %s (local time), %s (UTC)", time_val, time_str);
    ZITI_LOG(INFO,"	- log file location: %s", get_log_file_name());
    ZITI_LOG(INFO,"============================================================================");
    move_config_from_previous_windows_backup(global_loop_ref);

    ZITI_LOG(DEBUG, "granting se_debug privilege to current process to allow access to privileged processes during posture checks");
    //ensure this process has the necessary access token to get the full path of privileged processes
    if (!scm_grant_se_debug()){
        ZITI_LOG(WARN, "could not set se debug access token on process. if process posture checks seem inconsistent this may be why");
    }
#endif

    if (configured_log_level == NULL) {
        // set log level from instance/config, if NULL is returned, the default log level will be used
        const char *log_lvl = get_log_level_label();
        if (log_lvl != NULL) {
            ziti_log_set_level_by_label(log_lvl);
        }
    }
    ziti_tunnel_set_log_level(ziti_log_level(NULL, NULL));
    set_log_level(ziti_log_level_label());
    ziti_tunnel_set_logger(ziti_logger);

    if (init_proxy_connector(configured_proxy) != 0) {
        exit(1);
    }

    int rc;
    if (is_host_only()) {
        rc = run_tunnel_host_mode(global_loop_ref);
    } else {
        rc = run_tunnel(global_loop_ref, tun_ip, dns_ip, configured_cidr, dns_upstream);
    }
    exit(rc);
}

static int verbose_version;
static struct option version_options[] = {
        { "verbose", no_argument, NULL, 'v'},
};
static int version_opts(int argc, char *argv[]) {
    int c, option_index, errors = 0;
    optind = 0;

    while ((c = getopt_long(argc, argv, "v",
                            version_options, &option_index)) != -1) {
        switch (c) {
            case 'v':
                verbose_version = 1;
                break;
            default: {
                fprintf(stderr, "Unknown option '%c'\n", c);
                errors++;
                break;
            }
        }
    }

    CHECK_COMMAND_ERRORS(errors);

    return optind;
}

static void version() {
    if (verbose_version) {
        tls_context *tls = default_tls_context("", 0);
        printf("ziti-tunneler: %s\n"
               "ziti-sdk:      %s\n"
               "tlsuv:         %s[%s]\n",
               ziti_tunneler_version(), ziti_get_version()->version, tlsuv_version(), tls->version());
        tls->free_ctx(tls);
    } else {
        printf("%s\n", ziti_tunneler_version());
    }
}

static ziti_enroll_opts enroll_opts;
static char* config_file;

#if _WIN32
#ifndef PATH_MAX
#define PATH_MAX MAX_PATH
#endif
#define realpath(rel, abs) _fullpath(abs, rel, PATH_MAX)
#endif

static int parse_enroll_opts(int argc, char *argv[]) {
    static struct option opts[] = {
            { "jwt", required_argument, NULL, 'j'},
            { "identity", required_argument, NULL, 'i'},
            { "use-keychain", no_argument, NULL, 'K' },
            { "key", required_argument, NULL, 'k'},
            { "cert", required_argument, NULL, 'c'},
            { "name", required_argument, NULL, 'n'},
            { "proxy", required_argument, NULL, 'x' },
    };
    int c, option_index, errors = 0;
    const char *proxy_arg = NULL;
    optind = 0;

    while ((c = getopt_long(argc, argv, "j:i:Kk:c:n:x:",
                            opts, &option_index)) != -1) {
        switch (c) {
            case 'j':
                enroll_opts.jwt = optarg;
                break;
            case 'K':
                enroll_opts.use_keychain = true;
                break;
            case 'k': {
                uv_fs_t req = {};
                if (uv_fs_stat(NULL, &req, optarg, NULL) == 0
#if defined(S_ISREG)
                    && (S_ISREG(req.statbuf.st_mode)
#if defined(S_ISLNK)
                    || S_ISLNK(req.statbuf.st_mode)
#endif
                                           )
#endif
                        ) {
                    enroll_opts.enroll_key = realpath(optarg, NULL);
                } else {
                    // may be key ref (keychain/pkcs11)
                    enroll_opts.enroll_key = optarg;
                }
                uv_fs_req_cleanup(&req);
                break;
            }
            case 'c':
                enroll_opts.enroll_cert = realpath(optarg, NULL);
                break;
            case 'n':
                enroll_opts.enroll_name = optarg;
                break;
            case 'i':
                config_file = optarg;
                break;
            case 'x':
                proxy_arg = optarg;
                break;
            default: {
                fprintf(stderr, "Unknown option '%c'\n", c);
                errors++;
                break;
            }
        }
    }

    if (init_proxy_connector(proxy_arg) != 0) {
        errors++;
    }

    if (enroll_opts.jwt == NULL || config_file == NULL) {
        errors++;
    }

    CHECK_COMMAND_ERRORS(errors);

    return optind;
}

static void enroll_cb(const ziti_config *cfg, int status, const char *err, void *ctx) {
    struct enroll_cb_params *params = ctx;

    *params = (struct enroll_cb_params) { 0 };

    if (status != ZITI_OK) {
        ZITI_LOG(ERROR, "enrollment failed: %s(%d)", err, status);
        return;
    }

    size_t len;
    char *cfg_json = ziti_config_to_json(cfg, 0, &len);

    params->config.base = cfg_json;
    params->config.len = len;
}

static int write_close(FILE *fp, const uv_buf_t *data)
{
  size_t n;
  int rc = 0;

  /**
   * fwrite signals error by a short count.
   * Cstd does not specify errno, while
   * POSIX specifies that errno is set on error.
   */
  errno = 0;
  n = fwrite(data->base, data->len, 1, fp);
  if (n != 1) {
    rc = -errno;
    if (rc == 0)
      rc = -EIO;
  }

  if (fclose(fp) == EOF) {
    if (rc == 0)
      rc = -errno;
  }

  return rc;
}

static void enroll(int argc, char *argv[]) {
    uv_loop_t *l = uv_loop_new();
    int log_level = get_log_level(configured_log_level);
    ziti_log_init(global_loop_ref, log_level, NULL);
    if (init_proxy_connector(configured_proxy) != 0) {
        exit(EXIT_FAILURE);
    }

    if (config_file == 0) {
        ZITI_LOG(ERROR, "output file option(-i|--identity) is required");
        exit(EXIT_FAILURE);
    }

    if (enroll_opts.jwt == NULL) {
        ZITI_LOG(ERROR, "JWT file option(-j|--jwt) is required");
        exit(EXIT_FAILURE);
    }

    /* open with O_EXCL to fail if the file exists */
    int outfd = open(config_file, O_CREAT | O_WRONLY | O_EXCL, S_IRUSR | S_IWUSR);
    if (outfd < 0) {
        ZITI_LOG(ERROR, "failed to open file %s: %s(%d)", config_file, strerror(errno), errno);
        exit(EXIT_FAILURE);
    }
    FILE *outfile = NULL;
    if ((outfile = fdopen(outfd, "wb")) == NULL) {
        ZITI_LOG(ERROR, "failed to open file %s: %s(%d)", config_file, strerror(errno), errno);
        (void) close(outfd);
        exit(EXIT_FAILURE);
    }

    struct enroll_cb_params params = { 0 };

    ziti_enroll(&enroll_opts, l, enroll_cb, &params);

    uv_run(l, UV_RUN_DEFAULT);

    int rc;
    if (params.config.len > 0) {
        rc = write_close(outfile, &params.config);
        free(params.config.base);
        if (rc < 0) {
            ZITI_LOG(ERROR, "failed to write config file %s: %s (%d)",
                config_file, strerror(-rc), -rc);
        }
    } else {
        (void) fclose(outfile);
        rc = -1;
    }

    /* if unsuccessful, delete config_file and exit */
    if (rc < 0) {
        (void) unlink(config_file);
        exit(EXIT_FAILURE);
    }
}

static tunnel_command cmd = {
        .show_result = true, // consistent with old behaviour
};

static int dump_opts(int argc, char *argv[]) {
    static struct option opts[] = {
            {"identity", required_argument, NULL, 'i'},
            {"dump_path", required_argument, NULL, 'p'},
    };
    int c, option_index, errors = 0;
    optind = 0;

    tunnel_ziti_dump *dump_options = calloc(1, sizeof(tunnel_ziti_dump));
    cmd.command = TunnelCommand_ZitiDump;

    while ((c = getopt_long(argc, argv, "i:p:",
                            opts, &option_index)) != -1) {
        switch (c) {
            case 'i':
                dump_options->identifier = strdup(optarg);
                break;
            case 'p':
                dump_options->dump_path = realpath(optarg, NULL);
                break;
            default: {
                fprintf(stderr, "Unknown option '%c'\n", c);
                errors++;
                break;
            }
        }
    }

    CHECK_COMMAND_ERRORS(errors);

    size_t json_len;
    cmd.data = tunnel_ziti_dump_to_json(dump_options, MODEL_JSON_COMPACT, &json_len);
    if (dump_options != NULL) {
        free_tunnel_ziti_dump(dump_options);
        free(dump_options);
    }

    return optind;
}

static int ip_dump_opts(int argc, char *argv[]) {
    static struct option opts[] = {
            {"dump_path", required_argument, NULL, 'p'},
    };
    int c, option_index, errors = 0;
    optind = 0;

    tunnel_ip_dump *dump_options = calloc(1, sizeof(tunnel_ip_dump));
    cmd.command = TunnelCommand_IpDump;

    while ((c = getopt_long(argc, argv, "p:", opts, &option_index)) != -1) {
        switch (c) {
            case 'p':
                dump_options->dump_path = realpath(optarg, NULL);
                break;
            default: {
                fprintf(stderr, "Unknown option '%c'\n", c);
                errors++;
                break;
            }
        }
    }

    CHECK_COMMAND_ERRORS(errors);

    size_t json_len;
    cmd.data = tunnel_ip_dump_to_json(dump_options, MODEL_JSON_COMPACT, &json_len);
    if (dump_options != NULL) {
        free_tunnel_ip_dump(dump_options);
        free(dump_options);
    }

    return optind;
}

static int send_message_to_tunnel(char* message, bool show_result) {
#if _WIN32
    HANDLE cmd_soc = CreateFileA(sockfile,
                                 GENERIC_READ | GENERIC_WRITE,
                                 0, NULL,
                                 OPEN_EXISTING,
                                 FILE_FLAG_OVERLAPPED, NULL);
    if (cmd_soc == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        fprintf(stderr, "failed to connect to pipe: %lu", err);
        exit(1);
    }
#else
    uv_os_sock_t cmd_soc = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr = {
            .sun_family = AF_UNIX,
#if __APPLE__
            .sun_len = sizeof(addr),
#endif
    };
    strncpy(addr.sun_path, sockfile, sizeof(addr.sun_path));

    if (connect(cmd_soc, (const struct sockaddr *) &addr, sizeof(addr))) {
        perror("cmd socket connect");
    }

#endif
    size_t msg_size = strlen(message);
    size_t count = 0;
    while (count < strlen(message)) {
#if _WIN32
        DWORD c;
        if (!WriteFile(cmd_soc, message + count, msg_size - count, &c, NULL)) {
            fprintf(stderr, "failed to write to pipe: %lu", GetLastError());
            exit(1);
        }
#else
        ssize_t c;
        c = write(cmd_soc, message + count, msg_size - count);
#endif
        if (c < 0) {
            perror("write command");
            exit(1);
        }
        count += c;
    }

    struct json_tokener *parser = json_tokener_new();
    char buf[8*1024];
    struct json_object *json = NULL;
    while(json == NULL) {
#if _WIN32
        DWORD c;
        if (!ReadFile(cmd_soc, buf, sizeof(buf), &c, NULL)) {
            fprintf(stderr, "failed to read from pipe: %lu", GetLastError());
            exit(1);
        }
#else
        ssize_t c = read(cmd_soc, buf, sizeof(buf));
#endif
        if (c < 0) {
            perror("read resp");
            exit(1);
        }
        json = json_tokener_parse_ex(parser, buf, (int) c);
        if (json == NULL) {
            enum json_tokener_error e = json_tokener_get_error(parser);
            if (e != json_tokener_continue) {
                fprintf(stderr, "JSON parsing error: %s\n in payload: %.*s",
                        json_tokener_error_desc(e), (int)c, buf);
                exit(1);
            }
        }
    }

    if (show_result) {
        printf("%s\n", json_object_to_json_string_ext(json, JSON_C_TO_STRING_PRETTY));
    }
    int code = json_object_get_boolean(json_object_object_get(json, "Success")) ?
            0 : json_object_get_int(json_object_object_get(json, "Code"));
    json_object_put(json);
    json_tokener_free(parser);

    return code;
}

static void send_message_to_tunnel_fn(int argc, char *argv[]) {
    char* json = tunnel_command_to_json(&cmd, MODEL_JSON_COMPACT, NULL);
    int result = send_message_to_tunnel(json, cmd.show_result);
    free_tunnel_command(&cmd);
    free(json);
    exit(result);
}

// reusable parsing of a single required `-i` option
static char* get_identity_opt(int argc, char *argv[]) {
    static struct option opts[] = {
            {"identity", required_argument, NULL, 'i'},
    };
    int c, option_index, errors = 0;
    optind = 0;
    char *id = NULL;
    while ((c = getopt_long(argc, argv, "i:",
                            opts, &option_index)) != -1) {
        switch (c) {
            case 'i':
                id = optarg;
                break;
            default: {
                fprintf(stderr, "Unknown option '%c'\n", c);
                errors++;
                break;
            }
        }
    }

    if (id == NULL) {
        fprintf(stderr, "-i option is required");
        errors++;
    }
    CHECK_COMMAND_ERRORS(errors);
    return id;
}

static int ext_auth_opts(int argc, char *argv[]) {
    tunnel_identity_id id = {
            .identifier = (char*)get_identity_opt(argc, argv),
    };

    cmd.command = TunnelCommands.ExternalAuth;
    cmd.data = tunnel_identity_id_to_json(&id, MODEL_JSON_COMPACT, NULL);
    return optind;
}

static int on_off_identity_opts(int argc, char *argv[]) {
    static struct option opts[] = {
            {"identity", required_argument, NULL, 'i'},
            {"onoff", required_argument, NULL, 'o'}
    };
    int c, option_index, errors = 0;
    optind = 0;

    tunnel_on_off_identity on_off_identity_options = {0};
    cmd.command = TunnelCommand_IdentityOnOff;

    while ((c = getopt_long(argc, argv, "i:o:",
                            opts, &option_index)) != -1) {
        switch (c) {
            case 'i':
                on_off_identity_options.identifier = optarg;
                break;
            case 'o': {
                if (optarg[0] == 'T' || optarg[0] == 't') {
                    on_off_identity_options.onOff = true;
                } else {
                    on_off_identity_options.onOff = false;
                }
                break;
            }
            default: {
                fprintf(stderr, "Unknown option '%c'\n", c);
                errors++;
                break;
            }
        }
    }

    CHECK_COMMAND_ERRORS(errors);

    size_t json_len;
    cmd.data = tunnel_on_off_identity_to_json(&on_off_identity_options, MODEL_JSON_COMPACT, &json_len);
    on_off_identity_options.identifier = NULL; // don't try to free static memory (`optarg`)
    free_tunnel_on_off_identity(&on_off_identity_options);

    return optind;
}

static int enable_identity_opts(int argc, char *argv[]) {

    tunnel_load_identity load_identity_options = {
            .path = realpath(get_identity_opt(argc, argv), NULL),
    };
    cmd.command = TunnelCommand_LoadIdentity;

    size_t json_len;
    cmd.data = tunnel_load_identity_to_json(&load_identity_options, MODEL_JSON_COMPACT, &json_len);
    free_tunnel_load_identity(&load_identity_options);

    return optind;
}

static int enable_mfa_opts(int argc, char *argv[]) {
    tunnel_identity_id id = {
            .identifier = get_identity_opt(argc, argv),
    };
    cmd.command = TunnelCommand_EnableMFA;

    size_t json_len;
    cmd.data = tunnel_identity_id_to_json(&id, MODEL_JSON_COMPACT, &json_len);

    return optind;
}

static int verify_mfa_opts(int argc, char *argv[]) {
    static struct option opts[] = {
            {"identity", required_argument, NULL, 'i'},
            {"authcode", required_argument, NULL, 'c'},
    };
    int c, option_index, errors = 0;
    optind = 0;

    tunnel_verify_mfa *verify_mfa_options = calloc(1, sizeof(tunnel_verify_mfa));
    cmd.command = TunnelCommand_VerifyMFA;

    while ((c = getopt_long(argc, argv, "i:c:",
                            opts, &option_index)) != -1) {
        switch (c) {
            case 'i':
                verify_mfa_options->identifier = optarg;
                break;
            case 'c':
                verify_mfa_options->code = optarg;
                break;
            default: {
                fprintf(stderr, "Unknown option '%c'\n", c);
                errors++;
                break;
            }
        }
    }

    CHECK_COMMAND_ERRORS(errors);

    size_t json_len;
    cmd.data = tunnel_verify_mfa_to_json(verify_mfa_options, MODEL_JSON_COMPACT, &json_len);
    free(verify_mfa_options);

    return optind;
}

static int remove_mfa_opts(int argc, char *argv[]) {
    static struct option opts[] = {
            {"identity", required_argument, NULL, 'i'},
            {"authcode", required_argument, NULL, 'c'},
    };
    int c, option_index, errors = 0;
    optind = 0;

    tunnel_remove_mfa *remove_mfa_options = calloc(1, sizeof(tunnel_remove_mfa));
    cmd.command = TunnelCommand_RemoveMFA;

    while ((c = getopt_long(argc, argv, "i:c:",
                            opts, &option_index)) != -1) {
        switch (c) {
            case 'i':
                remove_mfa_options->identifier = optarg;
                break;
            case 'c':
                remove_mfa_options->code = optarg;
                break;
            default: {
                fprintf(stderr, "Unknown option '%c'\n", c);
                errors++;
                break;
            }
        }
    }

    CHECK_COMMAND_ERRORS(errors);

    size_t json_len;
    cmd.data = tunnel_remove_mfa_to_json(remove_mfa_options, MODEL_JSON_COMPACT, &json_len);
    free(remove_mfa_options);

    return optind;
}

static int submit_mfa_opts(int argc, char *argv[]) {
    static struct option opts[] = {
            {"identity", required_argument, NULL, 'i'},
            {"authcode", required_argument, NULL, 'c'},
    };
    int c, option_index, errors = 0;
    optind = 0;

    tunnel_submit_mfa *submit_mfa_options = calloc(1, sizeof(tunnel_submit_mfa));
    cmd.command = TunnelCommand_SubmitMFA;

    while ((c = getopt_long(argc, argv, "i:c:",
                            opts, &option_index)) != -1) {
        switch (c) {
            case 'i':
                submit_mfa_options->identifier = optarg;
                break;
            case 'c':
                submit_mfa_options->code = optarg;
                break;
            default: {
                fprintf(stderr, "Unknown option '%c'\n", c);
                errors++;
                break;
            }
        }
    }

    CHECK_COMMAND_ERRORS(errors);

    size_t json_len;
    cmd.data = tunnel_submit_mfa_to_json(submit_mfa_options, MODEL_JSON_COMPACT, &json_len);
    free(submit_mfa_options);

    return optind;
}

static int generate_mfa_codes_opts(int argc, char *argv[]) {
    static struct option opts[] = {
            {"identity", required_argument, NULL, 'i'},
            {"authcode", required_argument, NULL, 'c'},
    };
    int c, option_index, errors = 0;
    optind = 0;

    tunnel_generate_mfa_codes *mfa_codes_options = calloc(1, sizeof(tunnel_generate_mfa_codes));
    cmd.command = TunnelCommand_GenerateMFACodes;

    while ((c = getopt_long(argc, argv, "i:c:",
                            opts, &option_index)) != -1) {
        switch (c) {
            case 'i':
                mfa_codes_options->identifier = optarg;
                break;
            case 'c':
                mfa_codes_options->code = optarg;
                break;
            default: {
                fprintf(stderr, "Unknown option '%c'\n", c);
                errors++;
                break;
            }
        }
    }

    CHECK_COMMAND_ERRORS(errors);

    size_t json_len;
    cmd.data = tunnel_generate_mfa_codes_to_json(mfa_codes_options, MODEL_JSON_COMPACT, &json_len);
    free(mfa_codes_options);

    return optind;
}

static int get_mfa_codes_opts(int argc, char *argv[]) {
    static struct option opts[] = {
            {"identity", required_argument, NULL, 'i'},
            {"authcode", required_argument, NULL, 'c'},
    };
    int c, option_index, errors = 0;
    optind = 0;

    tunnel_get_mfa_codes *get_mfa_codes_options = calloc(1, sizeof(tunnel_get_mfa_codes));
    cmd.command = TunnelCommand_GetMFACodes;

    while ((c = getopt_long(argc, argv, "i:c:",
                            opts, &option_index)) != -1) {
        switch (c) {
            case 'i':
                get_mfa_codes_options->identifier = optarg;
                break;
            case 'c':
                get_mfa_codes_options->code = optarg;
                break;
            default: {
                fprintf(stderr, "Unknown option '%c'\n", c);
                errors++;
                break;
            }
        }
    }

    CHECK_COMMAND_ERRORS(errors);

    size_t json_len;
    cmd.data = tunnel_get_mfa_codes_to_json(get_mfa_codes_options, MODEL_JSON_COMPACT, &json_len);
    free(get_mfa_codes_options);

    return optind;
}

static int set_log_level_opts(int argc, char *argv[]) {
    static struct option opts[] = {
            {"loglevel", required_argument, NULL, 'l'},
    };
    int c, option_index, errors = 0;
    optind = 0;

    tunnel_set_log_level log_level_options = {0};
    while ((c = getopt_long(argc, argv, "l:",
                            opts, &option_index)) != -1) {
        switch (c) {
            case 'l':
                log_level_options.loglevel = optarg;
                break;
            default: {
                fprintf(stderr, "Unknown option '%c'\n", c);
                errors++;
                break;
            }
        }
    }

    if (log_level_options.loglevel == NULL) {
        fprintf(stderr, "symbolic level option(-l|--loglevel) is not specified, e.g., INFO, DEBUG\n");
        errors++;
    }

    CHECK_COMMAND_ERRORS(errors);

    cmd.command = TunnelCommand_SetLogLevel;

    size_t json_len;
    cmd.data = tunnel_set_log_level_to_json(&log_level_options, MODEL_JSON_COMPACT, &json_len);

    return optind;
}

static int update_tun_ip_opts(int argc, char *argv[]) {
    static struct option opts[] = {
            {"tunip", required_argument, NULL, 't'},
            {"prefixlength", required_argument, NULL, 'p'},
            {"addDNS", required_argument, NULL, 'd'},
    };
    int c, option_index, errors = 0;
    optind = 0;

    tunnel_tun_ip_v4 *tun_ip_v4_options = calloc(1, sizeof(tunnel_tun_ip_v4));
    cmd.command = TunnelCommand_UpdateTunIpv4;

    while ((c = getopt_long(argc, argv, "t:p:d:",
                            opts, &option_index)) != -1) {
        switch (c) {
            case 't':
                tun_ip_v4_options->tunIP = optarg;
                break;
            case 'p':
                tun_ip_v4_options->prefixLength = (int) strtol(optarg, NULL, 10);
                break;
            case 'd':
                if (strcmp(optarg, "true") == 0 || strcmp(optarg, "t") == 0 ) {
                    tun_ip_v4_options->addDns = true;
                } else {
                    tun_ip_v4_options->addDns = false;
                }
                break;
            default: {
                fprintf(stderr, "Unknown option '%c'\n", c);
                errors++;
                break;
            }
        }
    }

    CHECK_COMMAND_ERRORS(errors);

    size_t json_len;
    cmd.data = tunnel_tun_ip_v4_to_json(tun_ip_v4_options, MODEL_JSON_COMPACT, &json_len);
    free(tun_ip_v4_options);

    return optind;
}

static int endpoint_status_change_opts(int argc, char *argv[]) {
    static struct option opts[] = {
            {"wake", optional_argument, NULL, 'w'},
            {"unlock", optional_argument, NULL, 'u'},
    };
    int c, option_index, errors = 0;
    optind = 0;

    tunnel_status_change *tunnel_status_change_opts = calloc(1, sizeof(tunnel_status_change));
    cmd.command = TunnelCommand_StatusChange;

    while ((c = getopt_long(argc, argv, "w:u:",
                            opts, &option_index)) != -1) {
        switch (c) {
            case 'w':
                if (strcmp(optarg, "true") == 0 || strcmp(optarg, "t") == 0 ) {
                    tunnel_status_change_opts->woken = true;
                } else {
                    tunnel_status_change_opts->woken = false;
                }
                break;
            case 'u':
                if (strcmp(optarg, "true") == 0 || strcmp(optarg, "t") == 0 ) {
                    tunnel_status_change_opts->unlocked = true;
                } else {
                    tunnel_status_change_opts->unlocked = false;
                }
                break;
            default: {
                fprintf(stderr, "Unknown option '%c'\n", c);
                errors++;
                break;
            }
        }
    }

    CHECK_COMMAND_ERRORS(errors);

    size_t json_len;
    cmd.data = tunnel_status_change_to_json(tunnel_status_change_opts, MODEL_JSON_COMPACT, &json_len);
    free(tunnel_status_change_opts);

    return optind;
}

#if _WIN32
static void service_control(int argc, char *argv[]) {

    tunnel_service_control *tunnel_service_control_opt = calloc(1, sizeof(tunnel_service_control));
    if (parse_tunnel_service_control(tunnel_service_control_opt, cmd.data, strlen(cmd.data)) < 0) {
        fprintf(stderr, "Could not fetch service control data");
        return;
    }
    if (strcmp(tunnel_service_control_opt->operation, "install") == 0) {
        SvcInstall();
    } else if (strcmp(tunnel_service_control_opt->operation, "uninstall") == 0) {
        SvcDelete();
    } else if (strcmp(tunnel_service_control_opt->operation, "stop") == 0) {
        send_message_to_tunnel_fn(0, NULL);
    } else {
        fprintf(stderr, "Unknown option '%s'\n", tunnel_service_control_opt->operation);
    }

}

static int svc_opts(int argc, char *argv[]) {
    static struct option svc_opts[] = {
            {"operation", required_argument, NULL, 'o'},
    };

    tunnel_service_control *tunnel_service_control_options = calloc(1, sizeof(tunnel_service_control));
    cmd.command = TunnelCommand_ServiceControl;

    int c, option_index, errors = 0;
    optind = 0;

    while ((c = getopt_long(argc, argv, "o:",
                            svc_opts, &option_index)) != -1) {
        switch (c) {
            case 'o': {
                tunnel_service_control_options->operation = optarg;
                break;
            }
            default: {
                ZITI_LOG(ERROR, "Unknown option '%c'", c);
                errors++;
                break;
            }
        }
    }

    CHECK_COMMAND_ERRORS(errors);

    size_t json_len;
    cmd.data = tunnel_service_control_to_json(tunnel_service_control_options, MODEL_JSON_COMPACT, &json_len);

    return optind;
}
#endif

static int get_status_opts(int argc, char *argv[]) {
    optind = 0;

    cmd.command = TunnelCommand_Status;

    return optind;
}

static int delete_identity_opts(int argc, char *argv[]) {
    tunnel_identity_id id = {
            .identifier = get_identity_opt(argc, argv),
    };
    cmd.command = TunnelCommand_RemoveIdentity;

    size_t json_len;
    cmd.data = tunnel_identity_id_to_json(&id, MODEL_JSON_COMPACT, &json_len);

    return optind;
}


static int add_identity_opts(int argc, char *argv[]) {
    static struct option opts[] = {
            {"use-keychain", no_argument, NULL, 'K' },
            {"identity", required_argument, NULL, 'i'},
            {"jwt", required_argument, NULL, 'j'},
    };
    int c, option_index, errors = 0;
    optind = 0;

    tunnel_add_identity *tunnel_add_identity_opt = calloc(1, sizeof(tunnel_add_identity));
    cmd.command = TunnelCommand_AddIdentity;

    while ((c = getopt_long(argc, argv, "Ki:j:",
                            opts, &option_index)) != -1) {
        switch (c) {
            case 'K':
                tunnel_add_identity_opt->useKeychain = true;
                break;
            case 'i':
                tunnel_add_identity_opt->jwtFileName = optarg;
                break;
            case 'j':
                tunnel_add_identity_opt->jwtContent = optarg;
                break;
            default: {
                fprintf(stderr, "Unknown option '%c'\n", c);
                errors++;
                break;
            }
        }
    }

    CHECK_COMMAND_ERRORS(errors);

    size_t json_len;
    cmd.data = tunnel_add_identity_to_json(tunnel_add_identity_opt, MODEL_JSON_COMPACT, &json_len);
    free(tunnel_add_identity_opt);

    return optind;
}

static CommandLine enroll_cmd = make_command("enroll", "enroll Ziti identity",
        "-j|--jwt <enrollment token> -i|--identity <identity> [-k|--key <private_key> [-c|--cert <certificate>]] [-n|--name <name>]",
        "\t-j|--jwt\tenrollment token file\n"
        "\t-x|--proxy type://[username[:password]@]hostname_or_ip:port\tproxy to use when connecting to OpenZiti controller. 'http' is currently the only supported type.\n"
        "\t-i|--identity\toutput identity file\n"
        "\t-K|--use-keychain\tuse keychain to generate/store private key\n"
        "\t-k|--key\tprivate key for enrollment\n"
        "\t-c|--cert\tcertificate for enrollment\n"
        "\t-n|--name\tidentity name\n",
        parse_enroll_opts, enroll);
static CommandLine run_cmd = make_command("run", "run Ziti tunnel (required superuser access)",
                                          "-i <id.file> [-r N] [-v N] [-d|--dns-ip-range N.N.N.N/n]"
#ifdef __linux__
                                          " [--use-main-routing-table]"
#endif /*`__linux__ */
                                          ,
                                          "\t-i|--identity <identity>\trun with provided identity file (required)\n"
                                          "\t-I|--identity-dir <dir>\tload identities from provided directory\n"
                                          "\t-x|--proxy type://[username[:password]@]hostname_or_ip:port\tproxy to use when"
                                          " connecting to OpenZiti controller and edge routers. 'http' is currently the only supported type."
                                          "\t-v|--verbose N\tset log level, higher level -- more verbose (default 3)\n"
                                          "\t-r|--refresh N\tset service polling interval in seconds (default 10)\n"
                                          "\t-d|--dns-ip-range <ip range>\tspecify CIDR block in which service DNS names"
                                          " are assigned in N.N.N.N/n format (default " DEFAULT_DNS_CIDR ")\n"
#ifdef __linux__
                                          "\t--use-main-routing-table\tconfigure the main routing table\n"
#endif /* __linux__ */
                                          ,
        run_opts, run);
static CommandLine run_host_cmd = make_command("run-host", "run Ziti tunnel to host services",
                                          "-i <id.file> [-r N] [-v N]"
#ifdef __linux__
                                          " [--use-main-routing-table]"
#endif /* __linux__ */
                                          ,
                                          "\t-i|--identity <identity>\trun with provided identity file (required)\n"
                                          "\t-I|--identity-dir <dir>\tload identities from provided directory\n"
                                          "\t-x|--proxy type://[username[:password]@]hostname_or_ip:port\tproxy to use when"
                                          " connecting to OpenZiti controller and edge routers"
                                          "\t-v|--verbose N\tset log level, higher level -- more verbose (default 3)\n"
                                          "\t-r|--refresh N\tset service polling interval in seconds (default 10)\n"
#ifdef __linux__
                                          "\t--use-main-routing-table\tconfigure the main routing table\n"
#endif /* __linux__ */
                                          ,
                                          run_host_opts, run);
static CommandLine dump_cmd = make_command("dump", "dump the identities information", "[-i <identity>] [-p <dir>]",
                                           "\t-i|--identity\tdump identity info\n"
                                           "\t-p|--dump_path\tdump into path\n", dump_opts, send_message_to_tunnel_fn);
static CommandLine ip_dump_cmd = make_command("ip_dump", "dump ip stack information", "[-p <dir>]",
                                              "\t-p|--dump_path\tdump into path\n", ip_dump_opts, send_message_to_tunnel_fn);
static CommandLine on_off_id_cmd = make_command("on_off_identity", "enable/disable the identities information", "-i <identity> -o t|f",
                                           "\t-i|--identity\tidentity info that needs to be enabled/disabled\n"
                                                "\t-o|--onoff\t't' or 'f' to enable or disable the identity\n", on_off_identity_opts, send_message_to_tunnel_fn);
static CommandLine enable_id_cmd = make_command("enable", "enable the identities information", "[-i <identity>]",
                                                 "\t-i|--identity\tidentity info that needs to be enabled\n", enable_identity_opts, send_message_to_tunnel_fn);
static CommandLine enable_mfa_cmd = make_command("enable_mfa", "Enable MFA function fetches the totp url from the controller", "[-i <identity>]",
                                           "\t-i|--identity\tidentity info for enabling mfa\n", enable_mfa_opts, send_message_to_tunnel_fn);
static CommandLine verify_mfa_cmd = make_command("verify_mfa", "Verify the mfa login using the auth code while enabling mfa", "[-i <identity>] [-c <code>]",
                                                 "\t-i|--identity\tidentity info to verify mfa login\n"
                                                 "\t-c|--authcode\tauth code to verify mfa login\n", verify_mfa_opts, send_message_to_tunnel_fn);
static CommandLine remove_mfa_cmd = make_command("remove_mfa", "Removes MFA registration from the controller", "[-i <identity>] [-c <code>]",
                                                 "\t-i|--identity\tidentity info for removing mfa\n"
                                                 "\t-c|--authcode\tauth code to verify mfa login\n", remove_mfa_opts, send_message_to_tunnel_fn);
static CommandLine submit_mfa_cmd = make_command("submit_mfa", "Submit MFA code to authenticate to the controller", "[-i <identity>] [-c <code>]",
                                                 "\t-i|--identity\tidentity info for submitting mfa\n"
                                                 "\t-c|--authcode\tauth code to authenticate mfa login\n", submit_mfa_opts, send_message_to_tunnel_fn);
static CommandLine generate_mfa_codes_cmd = make_command("generate_mfa_codes", "Generate MFA codes", "[-i <identity>] [-c <code>]",
                                                 "\t-i|--identity\tidentity info for generating mfa codes\n"
                                                 "\t-c|--authcode\tauth code to authenticate the request for generating mfa codes\n", generate_mfa_codes_opts, send_message_to_tunnel_fn);
static CommandLine get_mfa_codes_cmd = make_command("get_mfa_codes", "Get MFA codes", "[-i <identity>] [-c <code>]",
                                                         "\t-i|--identity\tidentity info for fetching mfa codes\n"
                                                         "\t-c|--authcode\tauth code to authenticate the request for fetching mfa codes\n", get_mfa_codes_opts, send_message_to_tunnel_fn);
static CommandLine get_status_cmd = make_command("tunnel_status", "Get Tunnel Status", "", "", get_status_opts, send_message_to_tunnel_fn);
static CommandLine delete_id_cmd = make_command("delete", "delete the identities information", "[-i <identity>]",
                                                 "\t-i|--identity\tidentity info that needs to be deleted\n", delete_identity_opts, send_message_to_tunnel_fn);
static CommandLine add_id_cmd = make_command("add", "enroll and load the identity", "-j <jwt_content> -i <identity_name>",
                                                "\t-K|--use-keychain\tuse keychain to generate/store private key\n"
                                                "\t-j|--jwt\tenrollment token content\n"
                                                "\t-i|--identity\toutput identity .json file (relative to \"-I\" config directory)\n",
                                                add_identity_opts, send_message_to_tunnel_fn);
static CommandLine set_log_level_cmd = make_command("set_log_level", "Set log level of the tunneler", "-l <level>",
                                                    "\t-l|--loglevel\tlog level of the tunneler\n", set_log_level_opts, send_message_to_tunnel_fn);
static CommandLine update_tun_ip_cmd = make_command("update_tun_ip", "Update tun ip of the tunneler", "[-t <tunip>] [-p <prefixlength>] [-d <AddDNS>]",
                                                    "\t-t|--tunip\ttun ipv4 of the tunneler\n"
                                                    "\t-p|--prefixlength\ttun ipv4 prefix length of the tunneler\n"
                                                    "\t-d|--addDNS\tAdd Dns to the tunneler\n", update_tun_ip_opts, send_message_to_tunnel_fn);
static CommandLine ep_status_change_cmd = make_command("endpoint_sts_change", "send endpoint status change message to the tunneler", "[-w <wake>] [-u <unlock>]",
                                                    "\t-w|--wake\twake the tunneler\n"
                                                    "\t-u|--unlock\tunlock the tunneler\n", endpoint_status_change_opts, send_message_to_tunnel_fn);
static CommandLine ext_auth_login = make_command(
        "ext-jwt-login",
        "login with ext JWT signer", "-i <identity>",
        "\t-i|--identity\tidentity to authenticate\n",
        ext_auth_opts, send_message_to_tunnel_fn);

#if _WIN32
static CommandLine service_control_cmd = make_command("service_control", "execute service control functions for Ziti tunnel (required superuser access)",
                                          "-o|--operation <option>",
                                          "\t-o|--operation <option>\texecute the service control functions eg: install, uninstall and stop (required)\n",
                                          svc_opts, service_control);
#endif
static CommandLine ver_cmd = make_command("version", "show version", "[-v]", "\t-v\tshow verbose version information\n", version_opts, version);
static CommandLine help_cmd = make_command("help", "this message", NULL, NULL, NULL, usage);
static CommandLine *main_cmds[] = {
        &enroll_cmd,
        &run_cmd,
        &run_host_cmd,
        &on_off_id_cmd,
        &enable_id_cmd,
        &dump_cmd,
        &ip_dump_cmd,
        &enable_mfa_cmd,
        &verify_mfa_cmd,
        &remove_mfa_cmd,
        &submit_mfa_cmd,
        &generate_mfa_codes_cmd,
        &get_mfa_codes_cmd,
        &ext_auth_login,
        &get_status_cmd,
        &delete_id_cmd,
        &add_id_cmd,
        &set_log_level_cmd,
        &update_tun_ip_cmd,
#if _WIN32
        &service_control_cmd,
        &ep_status_change_cmd,
#endif
        &ver_cmd,
        &help_cmd,
        NULL
};

static CommandLine main_cmd = make_command_set(
        NULL,
        "Ziti Tunnel App",
        "<command> [<args>]", "to get help for specific command run 'ziti-edge-tunnel help <command>' "
                              "or 'ziti-edge-tunnel <command> -h'",
        NULL, main_cmds);

#if _WIN32

void endpoint_status_change_function(uv_loop_t *loop, void *ctx) {
    ZITI_LOG(VERBOSE, "invoking endpoint status change command");
    tunnel_status_change *status_change = ctx;

    // send status message immediately
    send_tunnel_status("status");

    // send endpoint status to the controller
    tunnel_command *tnl_cmd = calloc(1, sizeof(tunnel_command));
    tnl_cmd->command = TunnelCommand_StatusChange;
    size_t json_len;
    tnl_cmd->data = tunnel_status_change_to_json(status_change, MODEL_JSON_COMPACT, &json_len);
    send_tunnel_command_inline(tnl_cmd, NULL);
    free_tunnel_status_change(status_change);
    free(status_change);

}

void endpoint_status_change(bool woken, bool unlocked) {
    if (woken) {
        ZITI_LOG(INFO,"Received power resume event");
    }
    if (unlocked) {
        ZITI_LOG(INFO,"Received session unlocked event");
    }

    tunnel_status_change *status_change = calloc(1, sizeof(tunnel_status_change));
    status_change->woken = woken;
    status_change->unlocked = unlocked;

    ziti_tunnel_async_send(NULL, endpoint_status_change_function, status_change);
}

void scm_service_init(char *config_path) {
    started_by_scm = true;
    if (config_path != NULL) {
        config_dir = config_path;
    }
}

void scm_service_run(const char *name) {
    ZITI_LOG(INFO, "About to run tunnel service... %s", name);
    ziti_set_app_info(name, ziti_tunneler_version());
    run(0, NULL);
}

void stop_tunnel_and_cleanup() {
    ZITI_LOG(INFO, "Control request to stop tunnel service received...");

    ZITI_LOG(INFO,"notifying any clients of impending shutdown");
    send_tunnel_status("shutdown");

    // ziti dump to log file / stdout
    tunnel_command *tnl_cmd = calloc(1, sizeof(tunnel_command));
    tnl_cmd->command = TunnelCommand_ZitiDump;
    send_tunnel_command_inline(tnl_cmd, NULL);

    ZITI_LOG(INFO,"removing nrpt rules");
    remove_all_nrpt_rules();

    ZITI_LOG(INFO,"cleaning instance config ");
    cleanup_instance_config();

    ZITI_LOG(INFO,"============================ service ends ==================================");
    uv_cond_signal(&stop_cond); //release the wait condition held in scm_service_stop
}

void scm_service_stop_event(uv_loop_t *loop, void *arg) {
    //function used to get back onto the loop
    stop_tunnel_and_cleanup();
    if (arg != NULL && strcmp(arg, "interrupted") == 0 && loop != NULL) {
        uv_stop(loop);
        uv_loop_close(loop);
    }
}

// called by scm thread, it should not call any uv operations, because all uv operations except uv_async_send are not thread safe
void scm_service_stop() {
    ZITI_LOG(INFO,"stopping via service");
    uv_mutex_lock(&stop_mutex);
    ZITI_LOG(DEBUG,"mutex established. sending stop event");
    ziti_tunnel_async_send(tunneler, scm_service_stop_event, NULL);
    ZITI_LOG(INFO,"service stop waiting on condition...");
    uv_cond_wait(&stop_cond, &stop_mutex);
    uv_mutex_unlock(&stop_mutex);
}

static void move_config_from_previous_windows_backup(uv_loop_t *loop) {
    char *backup_folders[] = {
        "Windows.~BT\\Windows\\System32\\config\\systemprofile\\AppData\\Roaming\\NetFoundry",
        "Windows.old\\Windows\\System32\\config\\systemprofile\\AppData\\Roaming\\NetFoundry",
        NULL
    };

    char* system_drive = getenv("SystemDrive");

    for (int i =0; backup_folders[i]; i++) {
        char* config_dir_bkp = calloc(FILENAME_MAX, sizeof(char));
        sprintf(config_dir_bkp, "%s\\%s", system_drive, backup_folders[i]);
        uv_fs_t fs;
        int rc = uv_fs_access(loop, &fs, config_dir_bkp, 0, NULL);
        if (rc < 0) {
            uv_fs_req_cleanup(&fs);
            continue;
        }
        rc = uv_fs_scandir(loop, &fs, config_dir_bkp, 0, NULL);
        if (rc < 0) {
            ZITI_LOG(ERROR, "failed to scan dir[%s]: %d/%s", config_dir_bkp, rc, uv_strerror(rc));
            uv_fs_req_cleanup(&fs);
            continue;
        } else if (rc == 0) {
            uv_fs_req_cleanup(&fs);
            continue;
        }
        ZITI_LOG(TRACE, "scan dir %s, file count: %d", config_dir_bkp, rc);

        uv_dirent_t file;
        while (uv_fs_scandir_next(&fs, &file) == 0) {
            if (file.type == UV_DIRENT_FILE) {
                char old_file[FILENAME_MAX];
                snprintf(old_file, FILENAME_MAX, "%s\\%s", config_dir_bkp, file.name);
                char new_file[FILENAME_MAX];
                snprintf(new_file, FILENAME_MAX, "%s\\%s", config_dir, file.name);
                uv_fs_t fs_cpy;
                rc = uv_fs_copyfile(loop, &fs_cpy, old_file, new_file, 0, NULL);
                if (rc == 0) {
                    ZITI_LOG(INFO, "Restored old identity from the backup path - %s to new path - %s", old_file , new_file);
                    ZITI_LOG(INFO, "Removing old identity from the backup path - %s", old_file);
                    remove(old_file);
                } else {
                    ZITI_LOG(ERROR, "failed to copy backup identity file[%s]: %d/%s", old_file, rc, uv_strerror(rc));
                }
                uv_fs_req_cleanup(&fs_cpy);
            }
        }
        free(config_dir_bkp);
        config_dir_bkp = NULL;
        uv_fs_req_cleanup(&fs);
    }
}
#endif

static bool is_host_only() {
    return host_only;
}

bool use_rt_main(void) {
    return opt_prefer_rt_main > 0;
}

int main(int argc, char *argv[]) {
    const char *name = strrchr(argv[0], '/');
    if (name == NULL) {
        name = argv[0];
    } else {
        name = name + 1;
    }

    global_loop_ref = uv_default_loop();
    if (global_loop_ref == NULL) {
        printf("failed to initialize default uv loop"); //can't use ZITI_LOG here
        exit(EXIT_FAILURE);
    }

    main_cmd.name = name;
#if _WIN32
    SvcStart();

    // if service is started by SCM, SvcStart will return only when it receives the stop request
    // started_by_scm will be set to true only if scm initializes the config value
    // if the service is started from cmd line, SvcStart will return immediately and started_by_scm will be set to false. In this case tunnel can be run normally
    if (started_by_scm) {
        main_cmd.name = "Ziti Desktop Edge for Windows"; // when running as a service - it must have been installed by
                                                         // the ZDEW installer so let's use that name here
        printf("The service is stopped by SCM");
        return 0;
    }
#endif

    commandline_run(&main_cmd, argc, argv);
    return 0;
}

// ******* TUNNEL EVENT BROADCAST MESSAGES
IMPL_ENUM(event_severity, EVENT_SEVERITY)
IMPL_MODEL(status_event, STATUS_EVENT)
IMPL_MODEL(action_event, ACTION_EVENT)
IMPL_MODEL(identity_event, IDENTITY_EVENT)
IMPL_MODEL(services_event, SERVICES_EVENT)
IMPL_MODEL(tunnel_status_event, TUNNEL_STATUS_EVENT)
IMPL_MODEL(mfa_status_event, MFA_STATUS_EVENT)
IMPL_MODEL(tunnel_metrics_event, TUNNEL_METRICS_EVENT)
IMPL_MODEL(notification_message, TUNNEL_NOTIFICATION_MESSAGE)
IMPL_MODEL(notification_event, TUNNEL_NOTIFICATION_EVENT)

