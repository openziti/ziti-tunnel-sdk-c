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


#include <ziti/ziti_dns.h>
#include <ziti/ziti_tunnel_cbs.h>
#include <ziti/ziti_log.h>
#include <ziti/ziti_buffer.h>

#include "ziti_hosting.h"
#include "ziti_instance.h"

#include <tlsuv/http.h>

#include <string.h>
#include <stdarg.h>
#include <time.h>

#ifndef MAXBUFFERLEN
#define MAXBUFFERLEN 8192
#endif

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 254
#endif

#define FREE(x) do { if(x) free(x); x = NULL; } while(0)

// temporary list to pass info between parse and run
// static LIST_HEAD(instance_list, ziti_instance_s) instance_init_list;

// map<path -> ziti_instance>
static model_map instances;

static void on_ziti_event(ziti_context ztx, const ziti_event_t *event);

static const char * cfg_types[] = { "ziti-tunneler-client.v1", "intercept.v1", "ziti-tunneler-server.v1", "host.v1", NULL };

static unsigned long refresh_interval = 10;

static int process_cmd(const tunnel_command *cmd, void (*cb)(const tunnel_result *, void *ctx), void *ctx);
static int load_identity_cfg(const char *identifier, const ziti_config *cfg, bool disabled,
                             int api_page_size, command_cb cb, void *ctx);
static int load_identity(const char *identifier, const char *path, bool disabled, int api_page_size, command_cb cb, void *ctx);
static void get_transfer_rates(const char *identifier, command_cb cb, void *ctx);
static void load_ziti_async(uv_loop_t *loop, struct ziti_instance_s *inst);
static void on_sigdump(uv_signal_t *sig, int signum);
static void enable_mfa(ziti_context ztx, void *ctx);
static void verify_mfa(ziti_context ztx, char *code, void *ctx);
static void remove_mfa(ziti_context ztx, char *code, void *ctx);
// static void on_mfa_query(ziti_context ztx, void* mfa_ctx, ziti_auth_query_mfa *aq_mfa, ziti_ar_mfa_cb response_cb);
static void submit_mfa(ziti_context ztx, const char *code, void *ctx);
static void generate_mfa_codes(ziti_context ztx, char *code, void *ctx);
static void get_mfa_codes(ziti_context ztx, char *code, void *ctx);
static void tunnel_status_event(TunnelEvent event, int status, void *event_data, void *ctx);
static ziti_context get_ziti(const char *identifier);
static void update_config(uv_work_t *wr);
static void update_config_done(uv_work_t *wr, int err);
static void on_cmd_enroll(const ziti_config *cfg, int status, const char *err_message, void *ctx);

static void on_ext_auth(ziti_context ztx, const char *url, void *ctx);

struct tunnel_cb_s {
    void *ctx;
    command_cb cmd_cb;
    void *cmd_ctx;
};

typedef struct api_update_req_s {
    uv_work_t wr;
    ziti_context ztx;
    char *new_url;
    char *new_ca;
    int err;
    const char *errmsg;
} api_update_req;

static uv_signal_t sigusr1;

const ziti_tunnel_ctrl* ziti_tunnel_init_cmd(uv_loop_t *loop, tunneler_context tunnel_ctx, event_cb on_event) {
    CMD_CTX.loop = loop;
    CMD_CTX.tunnel_ctx = tunnel_ctx;
    CMD_CTX.on_event = on_event;
    CMD_CTX.ctrl.process = process_cmd;
    CMD_CTX.ctrl.load_identity = load_identity;
    CMD_CTX.ctrl.get_ziti = get_ziti;

#ifndef _WIN32
    uv_signal_init(loop, &sigusr1);
    uv_signal_start(&sigusr1, on_sigdump, SIGUSR1);
    uv_unref((uv_handle_t *) &sigusr1);
#endif

    return &CMD_CTX.ctrl;
}

#if _WIN32
#define realpath(rel, abs) _fullpath(abs, rel, MAX_PATH)
#endif

IMPL_ENUM(mfa_status, MFA_STATUS)

void ziti_set_refresh_interval(unsigned long seconds) {
    refresh_interval = seconds;
}

static ziti_context get_ziti(const char *identifier) {
    struct ziti_instance_s *inst = model_map_get(&instances, identifier);

    return inst ? inst->ztx : NULL;
}

static char * ziti_dump_to_string(void *ctx) {
    string_buf_t *out = new_string_buf();
    //actually invoke ziti_dump here
    ziti_dump(ctx, (int (*)(void *, const char *, ...)) string_buf_fmt, out);
    char *val =  string_buf_to_string(out, NULL);
    return val;
}

static int ziti_dump_to_file_op(void* fp, const char *fmt,  ...) {
    static char line[4096];

    va_list vargs;
    va_start(vargs, fmt);
    // write/append to file
    vfprintf(fp, fmt, vargs);
    va_end(vargs);

    return 0;
}

static void ziti_dump_to_file(void *ctx, char* outputFile) {
    FILE *fp;
    fp = fopen(outputFile, "w+");
    if(fp == NULL)
    {
        ZITI_LOG(ERROR, "Could not acquire file pointer of dump file: %s - %s", outputFile, strerror(errno));
        return;
    }
    uv_timeval64_t dump_time;
    uv_gettimeofday(&dump_time);

    char time_str[32];
    time_t sec = (time_t)dump_time.tv_sec;
    struct tm* start_tm = gmtime(&sec);
    strftime(time_str, sizeof(time_str), "%a %b %d %Y, %X %p", start_tm);

    fprintf(fp, "Ziti Dump starting: %s\n",time_str);

    //actually invoke ziti_dump here
    ziti_dump(ctx, ziti_dump_to_file_op, fp);
    fflush(fp);
    fclose(fp);
}

static void disconnect_identity(ziti_context ziti_ctx, void *tnlr_ctx) {
    ZITI_LOG(INFO, "Disconnecting Identity %s", ziti_get_identity(ziti_ctx)->name);
    remove_intercepts(ziti_ctx, tnlr_ctx);
    ziti_set_enabled(ziti_ctx, false);
}

bool is_null(const void * field, const char* message, tunnel_result* result) {
    if (field == NULL) {
        result->error = message;
        result->success = false;
        result->code = IPC_ERROR;
        return true;
    } else {
        return false;
    }
}

static int process_cmd(const tunnel_command *cmd, command_cb cb, void *ctx) {
    tunnel_result result = {
            .success = false,
            .error = NULL,
            .data = NULL,
            .code = IPC_ERROR,
    };
    ZITI_LOG(TRACE, "processing command[%s] with data[%s]", TunnelCommands.name(cmd->command), cmd->data);
    switch (cmd->command) {
        case TunnelCommand_LoadIdentity: {
            tunnel_load_identity load = {0};
            if (cmd->data == NULL || parse_tunnel_load_identity(&load, cmd->data, strlen(cmd->data)) < 0) {
                result.success = false;
                result.error = "invalid command";
                break;
            }

            int rc = ZITI_INVALID_CONFIG;
            if (load.config != NULL) {
                if (load.identifier == NULL) {
                    result.success = false;
                    result.code = rc;
                    result.error = "identifier is required when loading with config";
                    break;
                }
                rc = load_identity_cfg(load.identifier, load.config, false, (int)load.apiPageSize, cb, ctx);
            } else if (load.path != NULL) {
                const char *id = load.identifier ? load.identifier : load.path;
                rc = load_identity(id, load.path, false, (int)load.apiPageSize, cb, ctx);
            }

            if (rc == ZITI_OK) {
                return 0;
            }
            result.success = false;
            result.error = (char*)ziti_errorstr(rc);
            result.code = rc;
            break;
        }

        case TunnelCommand_ListIdentities: {
            tunnel_identity_lst id_list = {0};
            id_list.identities = calloc(model_map_size(&instances) + 1, sizeof(tunnel_identity_info*));
            const char *key;
            struct ziti_instance_s *inst;
            int idx = 0;
            MODEL_MAP_FOREACH(key, inst, &instances) {
                tunnel_identity_info *info = alloc_tunnel_identity_info();
                const ziti_identity *identity = ziti_get_identity(inst->ztx);
                info->name = strdup(identity->name);
                info->id = strdup(identity->id);
                info->network = strdup(ziti_get_controller(inst->ztx));
                info->config = strdup(key);

                id_list.identities[idx++] = info;
            }

            result.data = tunnel_identity_lst_to_json(&id_list, MODEL_JSON_COMPACT, NULL);
            result.success = true;
            result.code = IPC_SUCCESS;

            cb(&result, ctx);

            free_tunnel_identity_lst(&id_list);
            free(result.data);
            return 0;
        }

        case TunnelCommand_IdentityOnOff: {
            tunnel_on_off_identity on_off_id = {0};
            if (cmd->data == NULL || parse_tunnel_on_off_identity(&on_off_id, cmd->data, strlen(cmd->data)) < 0) {
                result.success = false;
                result.error = "invalid command";
                free_tunnel_on_off_identity(&on_off_id);
                break;
            }
            if (is_null(on_off_id.identifier, "Identifier info is not found in the request", &result)) {
                free_tunnel_on_off_identity(&on_off_id);
                break;
            }

            struct ziti_instance_s *inst = model_map_get(&instances, on_off_id.identifier);
            if (is_null(inst, "ziti context not found", &result) || is_null(inst->ztx, "ziti context is not loaded", &result)) {
                free_tunnel_on_off_identity(&on_off_id);
                break;
            }

            ziti_set_enabled(inst->ztx, on_off_id.onOff);
            result.data = tunnel_command_to_json(cmd, MODEL_JSON_COMPACT, NULL);
            result.success = true;
            result.code = IPC_SUCCESS;

            cb(&result, ctx);
            free_tunnel_on_off_identity(&on_off_id);
            free(result.data);
            return 0;
        }

        case TunnelCommand_ZitiDump: {
            #ifndef MAXPATHLEN
            #define MAXPATHLEN 1024
            #endif
            ZITI_LOG(INFO, "ziti dump started ");
            tunnel_ziti_dump dump = {0};
            if (cmd->data != NULL && parse_tunnel_ziti_dump(&dump, cmd->data, strlen(cmd->data)) < 0) {
                result.success = false;
                result.error = "invalid command";
                free_tunnel_ziti_dump(&dump);
                break;
            }
            const char *key;
            struct ziti_instance_s *inst;
            struct json_object *json = dump.dump_path == NULL ? 
                    json_object_new_object() : NULL;
            bool success = true;
            MODEL_MAP_FOREACH(key, inst, &instances) {
                if (inst->ztx == NULL) {
                    continue;
                }
                const ziti_identity *identity = ziti_get_identity(inst->ztx);
                if (identity == NULL) {
                    continue;
                }
                if (dump.identifier != NULL && strcmp(dump.identifier, inst->identifier) != 0) {
                    continue;
                }
                if (dump.dump_path == NULL) {
                    char *dumpstr = ziti_dump_to_string(inst->ztx);
                    struct json_object *s = json_object_new_string(dumpstr);
                    json_object_object_add(json, inst->identifier, s);
                    free(dumpstr);
                } else {
                    char dump_file[MAXPATHLEN];
                    char* dump_path = realpath(dump.dump_path, NULL);

                    if (dump_path != NULL) {
                        snprintf(dump_file, sizeof(dump_file), "%s/%s.ziti", dump_path, identity->name);
                        ziti_dump_to_file(inst->ztx, dump_file);
                    } else {
                        ZITI_LOG(WARN, "Could not generate the ziti dump file, because the path is not found");
                        success = false;
                    }
                }
            }
            if (success) {
                result.success = true;
                result.code = IPC_SUCCESS;
                if (json) {
                    result.data = strdup(json_object_to_json_string(json));
                    json_object_put(json);
                }
            } else {
                result.success = false;
                result.code = IPC_ERROR;
            }

            if (!result.success) {
                char errorMsg[1024];
                snprintf(errorMsg, sizeof(errorMsg),"No matching identifier found for %s", dump.identifier);
                result.error = errorMsg;
                ZITI_LOG(WARN, "%s", result.error);
            }
            ZITI_LOG(INFO, "ziti dump finished ");
            free_tunnel_ziti_dump(&dump);
            break;
        }

        case TunnelCommand_EnableMFA: {
            tunnel_identity_id id = {0};
            if (cmd->data != NULL && parse_tunnel_identity_id(&id, cmd->data, strlen(cmd->data)) < 0) {
                result.success = false;
                result.error = "invalid command";
                free_tunnel_identity_id(&id);
                break;
            }
            if (is_null(id.identifier, "Identifier info is not found in the request", &result)) {
                free_tunnel_identity_id(&id);
                break;
            }

            struct ziti_instance_s *inst = model_map_get(&instances, id.identifier);
            if (is_null(inst, "ziti context not found", &result) || is_null(inst->ztx, "ziti context is not loaded", &result)) {
                free_tunnel_identity_id(&id);
                break;
            }
            if (inst->ztx == NULL) {
                result.error = "ziti context is not loaded";
                result.success = false;
                break;
            }

            struct tunnel_cb_s *req = malloc(sizeof(struct tunnel_cb_s));
            req->ctx = (void*)id.identifier;
            id.identifier = NULL;
            req->cmd_cb = cb;
            req->cmd_ctx = ctx;

            enable_mfa(inst->ztx, req);

            free_tunnel_identity_id(&id);
            return 0;
        }

        case TunnelCommand_VerifyMFA: {
            tunnel_verify_mfa verify_mfa_cmd = {0};
            if (cmd->data != NULL && parse_tunnel_verify_mfa(&verify_mfa_cmd, cmd->data, strlen(cmd->data)) < 0) {
                result.success = false;
                result.error = "invalid command";
                free_tunnel_verify_mfa(&verify_mfa_cmd);
                break;
            }
            if (is_null(verify_mfa_cmd.identifier, "Identifier info is not found in the request", &result) || is_null(verify_mfa_cmd.code, "Authentication code is null", &result)) {
                free_tunnel_verify_mfa(&verify_mfa_cmd);
                break;
            }

            struct ziti_instance_s *inst = model_map_get(&instances, verify_mfa_cmd.identifier);
            if (is_null(inst, "ziti context not found", &result) || is_null(inst->ztx, "ziti context is not loaded", &result)) {
                free_tunnel_verify_mfa(&verify_mfa_cmd);
                break;
            }

            struct tunnel_cb_s *req = malloc(sizeof(struct tunnel_cb_s));
            req->ctx = strdup(verify_mfa_cmd.identifier);
            req->cmd_cb = cb;
            req->cmd_ctx = ctx;

            verify_mfa(inst->ztx, strdup(verify_mfa_cmd.code), req);

            free_tunnel_verify_mfa(&verify_mfa_cmd);
            return 0;
        }

        case TunnelCommand_RemoveMFA: {
            tunnel_remove_mfa remove_mfa_cmd = {0};
            if (cmd->data != NULL && parse_tunnel_remove_mfa(&remove_mfa_cmd, cmd->data, strlen(cmd->data)) < 0) {
                result.success = false;
                result.error = "invalid command";
                free_tunnel_remove_mfa(&remove_mfa_cmd);
                break;
            }
            if (is_null(remove_mfa_cmd.identifier, "Identifier info is not found in the request", &result) || is_null(remove_mfa_cmd.code, "Authentication code is null", &result)) {
                free_tunnel_remove_mfa(&remove_mfa_cmd);
                break;
            }

            struct ziti_instance_s *inst = model_map_get(&instances, remove_mfa_cmd.identifier);
            if (is_null(inst, "ziti context not found", &result) || is_null(inst->ztx, "ziti context is not loaded", &result)) {
                free_tunnel_remove_mfa(&remove_mfa_cmd);
                break;
            }

            struct tunnel_cb_s *req = malloc(sizeof(struct tunnel_cb_s));
            req->ctx = strdup(remove_mfa_cmd.identifier);
            req->cmd_cb = cb;
            req->cmd_ctx = ctx;

            remove_mfa(inst->ztx, strdup(remove_mfa_cmd.code), req);

            free_tunnel_remove_mfa(&remove_mfa_cmd);
            return 0;
        }

        case TunnelCommand_SubmitMFA: {
            tunnel_submit_mfa auth = {0};
            if (cmd->data == NULL || parse_tunnel_submit_mfa(&auth, cmd->data, strlen(cmd->data)) < 0) {
                result.error = "invalid command";
                result.success = false;
                free_tunnel_submit_mfa(&auth);
                break;
            }
            if (is_null(auth.identifier, "Identifier info is not found in the request", &result) || is_null(auth.code, "Authentication code is null", &result)) {
                free_tunnel_submit_mfa(&auth);
                break;
            }

            struct ziti_instance_s *inst = model_map_get(&instances, auth.identifier);
            if (is_null(inst, "ziti context not found", &result) || is_null(inst->ztx, "ziti context is not loaded", &result)) {
                free_tunnel_submit_mfa(&auth);
                break;
            }
            if (inst->ztx == NULL) {
                result.error = "ziti context is not loaded";
                result.success = false;
                break;
            }

            struct tunnel_cb_s *req = malloc(sizeof(struct tunnel_cb_s));
            req->ctx = strdup(auth.identifier);
            req->cmd_cb = cb;
            req->cmd_ctx = ctx;

            submit_mfa(inst->ztx, strdup(auth.code), req);
            free_tunnel_submit_mfa(&auth);
            return 0;
        }

        case TunnelCommand_GenerateMFACodes: {
            tunnel_generate_mfa_codes generate_mfa_codes_cmd = {0};
            if (cmd->data == NULL || parse_tunnel_generate_mfa_codes(&generate_mfa_codes_cmd, cmd->data, strlen(cmd->data)) < 0) {
                result.error = "invalid command";
                result.success = false;
                free_tunnel_generate_mfa_codes(&generate_mfa_codes_cmd);
                break;
            }
            if (is_null(generate_mfa_codes_cmd.identifier, "Identifier info is not found in the request", &result) || is_null(generate_mfa_codes_cmd.code, "Authentication code is null", &result)) {
                free_tunnel_generate_mfa_codes(&generate_mfa_codes_cmd);
                break;
            }

            struct ziti_instance_s *inst = model_map_get(&instances, generate_mfa_codes_cmd.identifier);
            if (is_null(inst, "ziti context not found", &result) || is_null(inst->ztx, "ziti context is not loaded", &result)) {
                free_tunnel_generate_mfa_codes(&generate_mfa_codes_cmd);
                break;
            }

            struct tunnel_cb_s *req = malloc(sizeof(struct tunnel_cb_s));
            req->ctx = strdup(generate_mfa_codes_cmd.identifier);
            req->cmd_cb = cb;
            req->cmd_ctx = ctx;

            generate_mfa_codes(inst->ztx, strdup(generate_mfa_codes_cmd.code), req);
            free_tunnel_generate_mfa_codes(&generate_mfa_codes_cmd);
            return 0;
        }

        case TunnelCommand_GetMFACodes: {
            tunnel_get_mfa_codes get_mfa_codes_cmd = {0};
            if (cmd->data == NULL || parse_tunnel_get_mfa_codes(&get_mfa_codes_cmd, cmd->data, strlen(cmd->data)) < 0) {
                result.error = "invalid command";
                result.success = false;
                free_tunnel_get_mfa_codes(&get_mfa_codes_cmd);
                break;
            }
            if (is_null(get_mfa_codes_cmd.identifier, "Identifier info is not found in the request", &result) || is_null(get_mfa_codes_cmd.code, "Authentication code is null", &result)) {
                free_tunnel_get_mfa_codes(&get_mfa_codes_cmd);
                break;
            }

            struct ziti_instance_s *inst = model_map_get(&instances, get_mfa_codes_cmd.identifier);
            if (is_null(inst, "ziti context not found", &result) || is_null(inst->ztx, "ziti context is not loaded", &result)) {
                free_tunnel_get_mfa_codes(&get_mfa_codes_cmd);
                break;
            }

            struct tunnel_cb_s *req = malloc(sizeof(struct tunnel_cb_s));
            req->ctx = strdup(get_mfa_codes_cmd.identifier);
            req->cmd_cb = cb;
            req->cmd_ctx = ctx;

            get_mfa_codes(inst->ztx, strdup(get_mfa_codes_cmd.code), req);
            free_tunnel_get_mfa_codes(&get_mfa_codes_cmd);
            return 0;
        }

        case TunnelCommand_GetMetrics: {
            tunnel_identity_id get_identity_metrics_cmd = {0};
            if (cmd->data == NULL || parse_tunnel_identity_id(&get_identity_metrics_cmd, cmd->data, strlen(cmd->data)) < 0) {
                result.error = "invalid command";
                result.success = false;
                free_tunnel_identity_id(&get_identity_metrics_cmd);
                break;
            }
            if (is_null(get_identity_metrics_cmd.identifier, "Identifier info is not found in the request", &result)) {
                free_tunnel_identity_id(&get_identity_metrics_cmd);
                break;
            }

            struct ziti_instance_s *inst = model_map_get(&instances, get_identity_metrics_cmd.identifier);
            if (is_null(inst, "ziti context not found", &result) || is_null(inst->ztx, "ziti context is not loaded", &result)) {
                free_tunnel_identity_id(&get_identity_metrics_cmd);
                break;
            }

            get_transfer_rates(get_identity_metrics_cmd.identifier, (command_cb) cb, ctx);
            free_tunnel_identity_id(&get_identity_metrics_cmd);
            return 0;
        }

        case TunnelCommand_RefreshIdentity: {
            tunnel_identity_id id = {0};
            if (cmd->data == NULL || parse_tunnel_identity_id(&id, cmd->data, strlen(cmd->data)) < 0) {
                result.success = false;
                result.error = "invalid command";
            } else if (!is_null(id.identifier,
                                "Identifier info is not found in the remove identity request",
                                &result)) {
                struct ziti_instance_s *inst = model_map_get(&instances, id.identifier);
                if (inst && inst->ztx) {
                    result.code = ziti_refresh(inst->ztx);
                    result.success = result.code == ZITI_OK;
                    result.error = result.code == ZITI_OK ? NULL : ziti_errorstr((int) result.code);
                } else {
                    result.error = "Identity not found";
                }
            }
            free_tunnel_identity_id(&id);
            break;
        }

        case TunnelCommand_RemoveIdentity: {
            tunnel_identity_id delete_id = {0};
            if (cmd->data == NULL || parse_tunnel_identity_id(&delete_id, cmd->data, strlen(cmd->data)) < 0) {
                result.success = false;
                result.error = "invalid command";
                free_tunnel_identity_id(&delete_id);
                break;
            }
            result.data = tunnel_command_to_json(cmd, MODEL_JSON_COMPACT, NULL);

            if (is_null(delete_id.identifier, "Identifier info is not found in the remove identity request", &result)) {
                free_tunnel_identity_id(&delete_id);
                break;
            }
            struct ziti_instance_s *inst = model_map_get(&instances, delete_id.identifier);

            if (is_null(inst, "ziti context not found", &result) || is_null(inst->ztx, "ziti context is not loaded", &result)) {
                free_tunnel_identity_id(&delete_id);
                break;
            }

            if (ziti_get_identity(inst->ztx)) {
                disconnect_identity(inst->ztx, CMD_CTX.tunnel_ctx);
            }
            model_map_remove(&instances, delete_id.identifier);
            result.success = true;
            result.code = IPC_SUCCESS;

            free_tunnel_identity_id(&delete_id);
            break;
        }

        case TunnelCommand_StatusChange: {
            tunnel_status_change tunnel_status_change_cmd = {0};
            if (cmd->data == NULL ||
                parse_tunnel_status_change(&tunnel_status_change_cmd, cmd->data, strlen(cmd->data)) < 0) {
                result.error = "invalid command";
                result.success = false;
                free_tunnel_status_change(&tunnel_status_change_cmd);
                break;
            }
            const char *key;
            struct ziti_instance_s *inst;
            MODEL_MAP_FOREACH(key, inst, &instances) {
                if (inst->ztx == NULL) {
                    continue;
                }
                ziti_endpoint_state_change(inst->ztx, tunnel_status_change_cmd.woken, tunnel_status_change_cmd.unlocked);
                ZITI_LOG(DEBUG, "Endpoint status change function is invoked for %s with woken %d and unlocked %d", inst->identifier,
                         tunnel_status_change_cmd.woken, tunnel_status_change_cmd.unlocked);
            }
            result.success = true;
            free_tunnel_status_change(&tunnel_status_change_cmd);
            break;
        }

        case TunnelCommand_Enroll: {
            tunnel_enroll enroll = {0};
            int rc;
            if (cmd->data == NULL || parse_tunnel_enroll(&enroll, cmd->data, strlen(cmd->data)) < 0) {
                result.error = "invalid command";
                result.success = false;
                free_tunnel_enroll(&enroll);
                break;
            } else {
                struct tunnel_cb_s *req = malloc(sizeof(struct tunnel_cb_s));
                req->cmd_cb = cb;
                req->cmd_ctx = ctx;

                ziti_enroll_opts opts = {
                        .enroll_name = enroll.name,
                        .jwt_content = enroll.jwt,
                        .enroll_key = enroll.key,
                        .enroll_cert = enroll.cert,
                        .use_keychain = enroll.use_keychain,
                };
                ziti_enroll(&opts, CMD_CTX.loop, on_cmd_enroll, req);
                free_tunnel_enroll(&enroll);
                return 0;
            }
        }

        case TunnelCommand_SetUpstreamDNS: {
            tunnel_upstream_dns_array upstreams = NULL;
            int rc;
            if (parse_tunnel_upstream_dns_array(&upstreams, cmd->data, strlen(cmd->data)) < 0) {
                result.error = "invalid command";
                result.success = false;
            } else if ((rc = ziti_dns_set_upstream(CMD_CTX.loop,upstreams)) != 0) {
                result.error = (char*)uv_strerror(rc);
                result.success = false;
            } else {
                result.success = true;
                result.code = IPC_SUCCESS;
            }
            free_tunnel_upstream_dns_array(&upstreams);
            break;
        }

        case TunnelCommand_ExternalAuth: {
            tunnel_identity_id id = {};
            if (cmd->data == NULL ||
                parse_tunnel_identity_id(&id, cmd->data, strlen(cmd->data)) < 0) {
                result.error = "invalid command";
                result.success = false;
                free_tunnel_identity_id(&id);
                break;
            }

            struct ziti_instance_s *inst = model_map_get(&instances, id.identifier);
            if (is_null(inst, "ziti context not found", &result) ||
                is_null(inst->ztx, "ziti context is not loaded", &result)) {
                free_tunnel_identity_id(&id);
                break;
            }

            struct tunnel_cb_s *req = calloc(1, sizeof(*req));
            req->ctx = (void*)id.identifier;
            req->cmd_cb = cb;
            req->cmd_ctx = ctx;
            ziti_ext_auth(inst->ztx, on_ext_auth, req);
            return 0;
        }
        default: {
            static char err[512];
            snprintf(err, sizeof(err), "unsupported command %d[%s]",
                     cmd->command, TunnelCommands.name(cmd->command));
            ZITI_LOG(VERBOSE, "%s", err);
            result.error = err;
            break;
        }
    }

    cb(&result, ctx);
    FREE(result.data);
    return 0;
}

static int load_identity(const char *identifier, const char *path, bool disabled, int api_page_size, command_cb cb, void *ctx) {
    ziti_config cfg = {0};
    int rc = ziti_load_config(&cfg, path);
    if (rc == ZITI_OK) {
        if (identifier == NULL) {
            identifier = path;
        }
        rc = load_identity_cfg(identifier, &cfg, disabled, api_page_size, cb, ctx);
    }

    free_ziti_config(&cfg);
    return rc;
}

static int load_identity_cfg(const char *identifier, const ziti_config *cfg, bool disabled, int api_page_size, command_cb cb, void *ctx) {
    struct ziti_instance_s *inst = new_ziti_instance(identifier ? identifier : cfg->cfg_source);
    ziti_options opts = {
            .api_page_size = api_page_size > 0 ? api_page_size : 0,
            .disabled = disabled,
    };
    int rc = init_ziti_instance(inst, cfg, &opts);
    if (rc != ZITI_OK) {
        goto on_error;
    }
    inst->load_cb = cb;
    inst->load_ctx = ctx;

    load_ziti_async(CMD_CTX.loop, inst);

    on_error:
    return rc;
}

static void get_transfer_rates(const char *identifier, command_cb cb, void *ctx) {
    struct ziti_instance_s *inst = model_map_get(&instances, identifier);
    if (inst->ztx == NULL) {
        return;
    }
    double up, down;
    ziti_get_transfer_rates(inst->ztx, &up, &down);
    tunnel_identity_metrics id_metrics = {
            .identifier = strdup(identifier),
    };
    int metrics_len = 6;
    if (up > 0) {
        char *ups = calloc((metrics_len + 1), sizeof(char));
        id_metrics.up = ups;
        snprintf(ups, metrics_len + 1, "%.2lf", up);
    }
    if (down > 0) {
        char *downs = calloc((metrics_len + 1), sizeof(char));
        id_metrics.down = downs;
        snprintf(downs, metrics_len+1, "%.2lf", down);
    }

    tunnel_result result = {0};
    result.success = true;
    result.code = IPC_SUCCESS;
    size_t json_len;
    result.data = tunnel_identity_metrics_to_json(&id_metrics, MODEL_JSON_COMPACT, &json_len);
    free_tunnel_identity_metrics(&id_metrics);
    cb(&result, ctx);
    free(result.data);
}

struct ziti_instance_s *new_ziti_instance(const char *identifier) {
    struct ziti_instance_s *inst = calloc(1, sizeof(struct ziti_instance_s));
    inst->identifier = strdup(identifier);
    return inst;
}

int init_ziti_instance(struct ziti_instance_s *inst, const ziti_config *cfg, const ziti_options *opts) {
    FREE(inst->ztx);
    int rc = ziti_context_init(&inst->ztx, cfg);
    if (rc != ZITI_OK) {
        ZITI_LOG(ERROR, "ziti_context_init failed: %s", ziti_errorstr(rc));
        return rc;
    }

    rc = ziti_context_set_options(inst->ztx, opts);
    if (rc != ZITI_OK) {
        ZITI_LOG(ERROR, "ziti_context_set_options failed: %s", ziti_errorstr(rc));
        FREE(inst->ztx);
        return rc;
    }

    rc = set_tnlr_options(inst);
    if (rc != ZITI_OK) {
        FREE(inst->ztx);
    }

    return rc;
}

int set_tnlr_options(struct ziti_instance_s *inst) {
    ziti_options tunneler_ziti_options = {
            .config_types = cfg_types,
            .event_cb = on_ziti_event, // ensure ziti events are propagated (as tunnel events) via the command interface
            .events = -1,
            .refresh_interval = (long)refresh_interval,
            .app_ctx = inst
    };
    int rc = ziti_context_set_options(inst->ztx, &tunneler_ziti_options);
    if (rc != ZITI_OK) {
        ZITI_LOG(ERROR, "ziti_context_set_options failed: %s", ziti_errorstr(rc));
        FREE(inst->ztx);
    }

    return rc;
}

void set_ziti_instance(const char *identifier, struct ziti_instance_s *inst) {
    model_map_set(&instances, identifier, inst);
}

void remove_ziti_instance(const char *identifier) {
    model_map_remove(&instances, identifier);
}

/** callback from ziti SDK when a new service becomes available to our identity */
static void on_service(ziti_context ziti_ctx, ziti_service *service, int status, void *tnlr_ctx) {
    ZITI_LOG(DEBUG, "service[%s]", service->name);
    tunneled_service_t *ts = ziti_sdk_c_on_service(ziti_ctx, service, status, tnlr_ctx);
    if (ts->intercept != NULL) {
        ZITI_LOG(INFO, "starting intercepting for service[%s]", service->name);
        protocol_t *proto;
//        STAILQ_FOREACH(proto, &ts->intercept->protocols, entries) {
//            address_t *address;
//            STAILQ_FOREACH(address, &ts->intercept->addresses, entries) {
//                port_range_t *pr;
//                STAILQ_FOREACH(pr, &ts->intercept->port_ranges, entries) {
//                    ZITI_LOG(INFO, "intercepting address[%s:%s:%s] service[%s]",
//                             proto->protocol, address->str, pr->str, service->name);
//                }
//            }
//        }

    }
    if (ts->host != NULL) {
        ZITI_LOG(INFO, "hosting server_address[%s] service[%s]", ts->host->display_address, service->name);
    }
}

static void on_ziti_event(ziti_context ztx, const ziti_event_t *event) {
    struct ziti_instance_s *instance = ziti_app_ctx(ztx);

    if (instance->ztx == NULL) {
        instance->ztx = ztx;
    }

    if (instance->ztx != ztx) {
        ZITI_LOG(ERROR, "something bad had happened: incorrect context");
    }

    const ziti_identity *identity = ziti_get_identity(ztx);
    const char *ctx_name = identity ? identity->name : instance->identifier;

    switch (event->type) {
        case ZitiContextEvent: {
            ziti_ctx_event ev = {0};
            ev.event_type = TunnelEvents.ContextEvent;
            ev.identifier = instance->identifier;
            ev.code = event->ctx.ctrl_status;
            if (event->ctx.ctrl_status == ZITI_OK) {
                ev.name = (char*)ctx_name;
                ev.version = ziti_get_controller_version(ztx)->version;
                ev.controller = (char *) ziti_get_controller(ztx);
                ZITI_LOG(INFO, "ziti_ctx[%s] connected to controller", ctx_name);
                ev.status = "OK";
                const char *ctrl = ziti_get_controller(ztx);

                struct tlsuv_url_s ctrl_url;
                if (tlsuv_parse_url(&ctrl_url, ctrl) == 0) {
                    char ctrl_hostname[HOST_NAME_MAX];
                    snprintf(ctrl_hostname, sizeof(ctrl_hostname), "%.*s", (int)ctrl_url.hostname_len, ctrl_url.hostname);
                    ziti_tunneler_exclude_route(CMD_CTX.tunnel_ctx, ctrl_hostname);
                } else {
                    ZITI_LOG(WARN, "failed to parse controller URL(%s)", ctrl);
                }

            } else {
                ZITI_LOG(WARN, "ziti_ctx controller connections failed: %s", ziti_errorstr(event->ctx.ctrl_status));
                ev.status = (char*)ziti_errorstr(event->ctx.ctrl_status);
            }
            CMD_CTX.on_event((const base_event *) &ev);
            break;
        }

        case ZitiServiceEvent: {
            ziti_service **zs;
            service_event ev = {
                    .event_type = TunnelEvents.ServiceEvent,
                    .identifier = instance->identifier,
            };

            bool send_event = false;
            if (event->service.removed != NULL) {
                ev.removed_services = event->service.removed;
                for (zs = event->service.removed; *zs != NULL; zs++) {
                    send_event = true;
                    on_service(ztx, *zs, ZITI_SERVICE_UNAVAILABLE, CMD_CTX.tunnel_ctx);
                }
            }

            if (event->service.added != NULL) {
                ev.added_services = event->service.added;
                for (zs = event->service.added; *zs != NULL; zs++) {
                    send_event = true;
                    on_service(ztx, *zs, ZITI_OK, CMD_CTX.tunnel_ctx);
                }
            }

            // need to send added/removed first because changes clobber both
            if (send_event) {
                CMD_CTX.on_event((const base_event *) &ev);
            }

            if (event->service.changed != NULL) {
                ev.added_services = event->service.changed;
                ev.removed_services = event->service.changed;
                send_event = false;
                for (zs = event->service.changed; *zs != NULL; zs++) {
                    send_event = true;
                    on_service(ztx, *zs, ZITI_OK, CMD_CTX.tunnel_ctx);
                }
                if (send_event) {
                    CMD_CTX.on_event((const base_event *) &ev);
                }
            }

            ziti_tunnel_commit_routes(CMD_CTX.tunnel_ctx);
            break;
        }

        case ZitiRouterEvent: {
            const struct ziti_router_event *rt_event = &event->router;
            switch (rt_event->status) {
                case EdgeRouterAdded:
                    ZITI_LOG(INFO, "ztx[%s] added edge router %s@%s", ctx_name, rt_event->name, rt_event->address);
                    ziti_tunneler_exclude_route(CMD_CTX.tunnel_ctx, rt_event->address);
                    break;
                case EdgeRouterConnected:
                    ZITI_LOG(INFO, "ztx[%s] router %s connected", ctx_name, rt_event->name);
                    break;
                case EdgeRouterDisconnected:
                    ZITI_LOG(INFO, "ztx[%s] router %s disconnected", ctx_name, rt_event->name);
                    break;
                case EdgeRouterRemoved:
                    ZITI_LOG(INFO, "ztx[%s] router %s removed", ctx_name, rt_event->name);
                    break;
                case EdgeRouterUnavailable:
                    ZITI_LOG(INFO, "ztx[%s] router %s is unavailable", ctx_name, rt_event->name);
                    break;
            }
            break;
        }

        case ZitiAuthEvent :
            if (event->auth.action == ziti_auth_prompt_totp) {
                ZITI_LOG(INFO, "ztx[%s/%s] Mfa event received", instance->identifier, ctx_name);
                mfa_event ev = {0};
                ev.event_type = TunnelEvents.MFAEvent;
                ev.identifier = instance->identifier;
                ev.operation = mfa_status_name(mfa_status_auth_challenge);
                CMD_CTX.on_event((const base_event *) &ev);
            } else if (event->auth.action == ziti_auth_login_external) {
                ZITI_LOG(INFO, "ztx[%s/%s] ext auth event received", instance->identifier, ctx_name);
                ext_signer_event ev = {0};
                ev.event_type = TunnelEvents.ExtJWTEvent;
                ev.identifier = instance->identifier;
                ev.status = "login_with_ext_signer";

                ziti_jwt_signer *signer;
                MODEL_LIST_FOREACH(signer, event->auth.providers) {
                    jwt_provider *provider = calloc(1, sizeof(*provider));
                    provider->name = signer->name;
                    provider->issuer = signer->provider_url;
                    model_list_append(&ev.providers, provider);
                }
                CMD_CTX.on_event((const base_event *) &ev);
                model_list_clear(&ev.providers, free);
            }
            break;

        case ZitiAPIEvent: {
            if (event->api.new_ctrl_address || event->api.new_ca_bundle) {
                if (instance->config_path) {
                    api_update_req *req = calloc(1, sizeof(api_update_req));
                    req->wr.data = req;
                    req->ztx = ztx;
                    req->new_url = event->api.new_ctrl_address ? strdup(event->api.new_ctrl_address) : NULL;
                    req->new_ca = event->api.new_ca_bundle ? strdup(event->api.new_ca_bundle) : NULL;
                    uv_queue_work(CMD_CTX.loop, &req->wr, update_config, update_config_done);
                }

                api_event ev = {0};
                ev.event_type = TunnelEvents.APIEvent;
                ev.identifier = instance->identifier;
                ev.new_ctrl_address = event->api.new_ctrl_address;
                ev.new_ca_bundle = event->api.new_ca_bundle;
                CMD_CTX.on_event((const base_event *) &ev);
            } else {
                ZITI_LOG(WARN, "unexpected API event: new_ctrl_address is missing");
            }
            break;
        }

        default:
            ZITI_LOG(WARN, "unhandled event type[%d]", event->type);

    }
}

static void load_ziti_async(uv_loop_t *loop, struct ziti_instance_s *inst) {
    tunnel_result result = {
            .success = true,
            .error = NULL,
            .code = IPC_SUCCESS,
    };

    ZITI_LOG(INFO, "attempting to load ziti instance[%s]", inst->identifier);
    if (model_map_get(&instances, inst->identifier) != NULL) {
        ZITI_LOG(WARN, "ziti context already loaded for %s", inst->identifier);
        result.success = false;
        result.error = "context already loaded";
        result.code = IPC_ERROR;
    } else {
        ZITI_LOG(INFO, "loading ziti instance[%s]", inst->identifier);
        if (ziti_context_run(inst->ztx, loop) == ZITI_OK) {
            model_map_set(&instances, inst->identifier, inst);
        } else {
            result.success = false;
            result.error = "failed to initialize ziti";
            result.code = IPC_ERROR;
        }
    }

    inst->load_cb(&result, inst->load_ctx);
    inst->load_ctx = NULL;
    inst->load_cb = NULL;

    if (!result.success) {
        free(inst);
    }
}

static void on_submit_mfa(ziti_context ztx, int status, void *ctx) {
    struct tunnel_cb_s *req = ctx;
    tunnel_result result = {0};
    if (status != ZITI_OK) {
        result.success = false;
        result.error = (char*)ziti_errorstr(status);
        result.code = IPC_ERROR;
    } else {
        result.success = true;
        result.code = IPC_SUCCESS;
    }

    if (req->cmd_cb) {
        req->cmd_cb(&result, req->cmd_ctx);
    }

    struct ziti_instance_s *inst = ziti_app_ctx(ztx);
    mfa_event *ev = calloc(1, sizeof(mfa_event));
    ev->operation = strdup(mfa_status_name(mfa_status_mfa_auth_status));
    ev->operation_type = mfa_status_mfa_auth_status;
    tunnel_status_event(TunnelEvent_MFAStatusEvent, status, ev, inst);

    if (status == ZITI_OK) {
        inst->mfa_req = NULL;
    }
    if (req->ctx){
        free(req->ctx);
    }
    free(req);
}

static void submit_mfa(ziti_context ztx, const char *code, void *ctx) {
    ziti_mfa_auth(ztx, code, on_submit_mfa, ctx);
    free((char *) code);
}

static void on_enable_mfa(ziti_context ztx, int status, ziti_mfa_enrollment *enrollment, void *ctx) {
    // send the response from enroll mfa to client
    struct tunnel_cb_s *req = ctx;
    tunnel_result result = {0};
    if (status != ZITI_OK) {
        result.success = false;
        result.error = (char*)ziti_errorstr(status);
        result.code = IPC_ERROR;
    } else {
        result.success = true;
        result.code = IPC_SUCCESS;

        tunnel_mfa_enrol_res enrol_res = {0};
        enrol_res.identifier = strdup(req->ctx);
        enrol_res.is_verified = enrollment->is_verified;
        enrol_res.provisioning_url = strdup(enrollment->provisioning_url);
        enrol_res.recovery_codes = enrollment->recovery_codes;
        size_t json_len;
        result.data = tunnel_mfa_enrol_res_to_json(&enrol_res, MODEL_JSON_COMPACT, &json_len);
        enrol_res.recovery_codes = NULL;
        free_tunnel_mfa_enrol_res(&enrol_res);
    }
    if (req->cmd_cb) {
        req->cmd_cb(&result, req->cmd_ctx);
    }

    struct ziti_instance_s *inst = ziti_app_ctx(ztx);
    mfa_event *ev = calloc(1, sizeof(mfa_event));
    ev->operation = strdup(mfa_status_name(mfa_status_enrollment_challenge));
    if (status == ZITI_OK) {
        ev->operation_type = mfa_status_enrollment_challenge;
        ev->provisioning_url = strdup(enrollment->provisioning_url);
        const char **rc = enrollment->recovery_codes;
        int size = 0;
        while (rc != NULL && *rc != NULL) {
            rc++;
            size++;
        }
        ev->recovery_codes = calloc((size + 1), sizeof(char *));
        if(enrollment->recovery_codes != NULL) {
            int idx;
            for (idx = 0; enrollment->recovery_codes[idx] != 0; idx++) {
                ev->recovery_codes[idx] = strdup(enrollment->recovery_codes[idx]);
            }
        }
    }

    tunnel_status_event(TunnelEvent_MFAStatusEvent, status, ev, inst);

    if (req->ctx) {
        free(req->ctx);
    }
    FREE(result.data);
    free(req);
}

static void enable_mfa(ziti_context ztx, void *ctx) {
    ziti_mfa_enroll(ztx, on_enable_mfa, ctx);
}

static void on_verify_mfa(ziti_context ztx, int status, void *ctx) {
// send the response from verify mfa to client
    struct tunnel_cb_s *req = ctx;
    tunnel_result result = {0};
    if (status != ZITI_OK) {
        result.success = false;
        result.error = (char*)ziti_errorstr(status);
        result.code = IPC_ERROR;
    } else {
        result.success = true;
        result.code = IPC_SUCCESS;
    }
    if (req->cmd_cb) {
        req->cmd_cb(&result, req->cmd_ctx);
    }

    struct ziti_instance_s *inst = ziti_app_ctx(ztx);
    mfa_event *ev = calloc(1, sizeof(mfa_event));
    ev->operation = strdup(mfa_status_name(mfa_status_enrollment_verification));
    ev->operation_type = mfa_status_enrollment_verification;
    tunnel_status_event(TunnelEvent_MFAStatusEvent, status, ev, inst);

    if (req->ctx) {
        free(req->ctx);
    }
    free(req);
}

static void verify_mfa(ziti_context ztx, char *code, void *ctx) {
    ziti_mfa_verify(ztx, code, on_verify_mfa, ctx);
}

static void on_remove_mfa(ziti_context ztx, int status, void *ctx) {
// send the response from verify mfa to client
    struct tunnel_cb_s *req = ctx;
    tunnel_result result = {0};
    if (status != ZITI_OK) {
        result.success = false;
        result.error = (char*)ziti_errorstr(status);
        result.code = IPC_ERROR;
    } else {
        result.success = true;
        result.code = IPC_SUCCESS;
    }
    if (req->cmd_cb) {
        req->cmd_cb(&result, req->cmd_ctx);
    }

    struct ziti_instance_s *inst = ziti_app_ctx(ztx);
    mfa_event *ev = calloc(1, sizeof(mfa_event));
    ev->operation = strdup(mfa_status_name(mfa_status_enrollment_remove));
    ev->operation_type = mfa_status_enrollment_remove;
    tunnel_status_event(TunnelEvent_MFAStatusEvent, status, ev, inst);

    if (req->ctx) {
        free(req->ctx);
    }
    free(req);
}

static void remove_mfa(ziti_context ztx, char *code, void *ctx) {
    ziti_mfa_remove(ztx, code, on_remove_mfa, ctx);
}

static void on_mfa_recovery_codes(ziti_context ztx, int status, const char **recovery_codes, void *ctx) {
    struct tunnel_cb_s *req = ctx;
    tunnel_result result = {0};
    if (status != ZITI_OK) {
        result.success = false;
        result.error = (char*)ziti_errorstr(status);
        result.code = IPC_ERROR;
    } else {
        result.success = true;
        result.code = IPC_SUCCESS;

        tunnel_mfa_recovery_codes mfa_recovery_codes = {0};
        mfa_recovery_codes.identifier = strdup(req->ctx);
        mfa_recovery_codes.recovery_codes = (model_string_array) recovery_codes;

        size_t json_len;
        result.data = tunnel_mfa_recovery_codes_to_json(&mfa_recovery_codes, MODEL_JSON_COMPACT, &json_len);
        mfa_recovery_codes.recovery_codes = NULL;
        free_tunnel_mfa_recovery_codes(&mfa_recovery_codes);
    }
    if (req->cmd_cb) {
        req->cmd_cb(&result, req->cmd_ctx);
    }
    if (req->ctx) {
        free(req->ctx);
    }
    FREE(result.data);
    free(req);
}

static void generate_mfa_codes(ziti_context ztx, char *code, void *ctx) {
    ziti_mfa_new_recovery_codes(ztx, code, on_mfa_recovery_codes, ctx);
}

static void get_mfa_codes(ziti_context ztx, char *code, void *ctx) {
    ziti_mfa_get_recovery_codes(ztx, code, on_mfa_recovery_codes, ctx);
}

static void on_cmd_enroll(const ziti_config *cfg, int status, const char *err_message, void *ctx) {
    struct tunnel_cb_s *req = ctx;
    char *cfg_json = cfg ? ziti_config_to_json(cfg, MODEL_JSON_COMPACT, NULL) : NULL;

    tunnel_result result = {
            .success = (status == ZITI_OK),
            .error = (char*)err_message,
            .code = status,
            .data = cfg_json,
    };

    req->cmd_cb(&result, req->cmd_ctx);
    free(cfg_json);
}

static void on_ext_auth(ziti_context ztx, const char *url, void *ctx) {
    struct tunnel_cb_s *req = ctx;
    tunnel_result result = {
            .success = true,
            .code = IPC_SUCCESS,
    };
    if (req->cmd_cb) {
        tunnel_ext_auth auth = {
                .identifier = (char*)req->ctx,
                .ext_auth_url = (char*)url,
        };
        result.data = tunnel_ext_auth_to_json(&auth, MODEL_JSON_COMPACT, NULL);

        req->cmd_cb(&result, req->cmd_ctx);
    }
    FREE(result.data);
    FREE(req->ctx);
    free(req);
}

#define CHECK(lbl, op) do{ \
int rc = (op);                  \
if (rc < 0) {              \
ZITI_LOG(ERROR, "operation[%s] failed: %d(%s) errno=%d", #op, rc, strerror(rc), errno); \
goto lbl;\
}                           \
}while(0)

static void tunnel_status_event(TunnelEvent event, int status, void *event_data, void *ctx) {

    switch(event) {
        case TunnelEvent_MFAStatusEvent:{
            mfa_event *ev = event_data;
            ev->event_type = TunnelEvents.MFAStatusEvent;
            struct ziti_instance_s *inst = ctx;
            ev->identifier = strdup(inst->identifier);
            ev->code = status;
            if (status != ZITI_OK) {
                ev->status = strdup((char*)ziti_errorstr(status));
            }
            CMD_CTX.on_event((const base_event *) ev);
            break;
        }

        case TunnelEvent_Unknown:
        default:
            ZITI_LOG(WARN, "unhandled event received: %d", event);
            break;
    }

}

static void on_sigdump(uv_signal_t *sig, int signum) {
#ifndef MAXPATHLEN
#define MAXPATHLEN 1024
#endif
    char fname[MAXPATHLEN];
    snprintf(fname, sizeof(fname), "/tmp/ziti-dump.%lu.dump", (unsigned long)uv_os_getpid());
    ZITI_LOG(INFO, "saving Ziti dump to %s", fname);
    FILE *dumpfile = fopen(fname, "a+");
    if (dumpfile == NULL) {
        ZITI_LOG(ERROR, "failed to open dump output file(%s): %d(%s)", fname, errno, strerror(errno));
        return;
    }

    uv_timeval64_t dump_time;
    uv_gettimeofday(&dump_time);

    char time_str[32];
    time_t sec = (time_t)dump_time.tv_sec;
    struct tm* start_tm = gmtime(&sec);
    strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%S", start_tm);

    CHECK(cleanup, fprintf(dumpfile, "ZIti Dump starting: %s\n",time_str));
    const char *k;
    struct ziti_instance_s *inst;
    MODEL_MAP_FOREACH(k, inst, &instances) {
        CHECK(cleanup, fprintf(dumpfile, "instance: %s\n", k));
        ziti_dump(inst->ztx, (int (*)(void *, const char *, ...)) fprintf, dumpfile);
    }

    CHECK(cleanup, fflush(dumpfile));
    cleanup:
    fclose(dumpfile);
}


static int update_file(const char *path, char *content, size_t content_len) {
#define CHECK_UV(desc, op) do{ \
    uv_fs_req_cleanup(&fs_req); \
    rc = op;             \
    if (rc < 0) {           \
        ZITI_LOG(ERROR, "op[" desc "] failed: %d(%s)", rc, uv_strerror(rc)); \
        goto DONE;               \
    }} while(0)

    int rc = 0;
    uv_fs_t fs_req = {0};
    CHECK_UV("check exiting config", uv_fs_stat(NULL, &fs_req, path, NULL));
    uint64_t mode = fs_req.statbuf.st_mode;

    char backup[FILENAME_MAX];
    snprintf(backup, sizeof(backup), "%s.bak", path);
    CHECK_UV("create backup", uv_fs_rename(NULL, &fs_req, path, backup, NULL));

    uv_os_fd_t f;
    CHECK_UV("open new config", f = uv_fs_open(NULL, &fs_req, path, UV_FS_O_WRONLY | UV_FS_O_CREAT, (int) mode, NULL));
    uv_buf_t buf = uv_buf_init(content, content_len);
    CHECK_UV("write new config", uv_fs_write(NULL, &fs_req, f, &buf, 1, 0, NULL));
    CHECK_UV("close new config", uv_fs_close(NULL, &fs_req, f, NULL));

    DONE:
    return rc;
#undef CHECK_UV
}

#define CHECK_UV(desc, op) do{ \
int rc = op;             \
if (rc < 0) {           \
req->err = rc;           \
req->errmsg = uv_strerror(rc); \
ZITI_LOG(ERROR, "op[" desc "] failed: %d(%s)", req->err, req->errmsg); \
goto DONE;               \
}} while(0)

static void update_config(uv_work_t *wr) {
    api_update_req *req = wr->data;
    struct ziti_instance_s *inst = ziti_app_ctx(req->ztx);
    const char *config_file = inst->config_path;
    size_t cfg_len;
    char *cfg_buf = NULL;
    uv_file f;

    uv_fs_t fs_req;
    CHECK_UV("check exiting config", uv_fs_stat(wr->loop, &fs_req, config_file, NULL));
    cfg_len = fs_req.statbuf.st_size;

    cfg_buf = malloc(cfg_len);
    CHECK_UV("open existing config", f = uv_fs_open(wr->loop, &fs_req, config_file, UV_FS_O_RDONLY, 0, NULL));
    uv_buf_t buf = uv_buf_init(cfg_buf, cfg_len);
    CHECK_UV("read existing config", uv_fs_read(wr->loop, &fs_req, f, &buf, 1, 0, NULL));
    CHECK_UV("close existing config", uv_fs_close(wr->loop, &fs_req, f, NULL));

    ziti_config cfg = {0};
    if (parse_ziti_config(&cfg, cfg_buf, fs_req.statbuf.st_size) < 0) {
        ZITI_LOG(ERROR, "failed to parse config file[%s]", config_file);
        req->err = -1;
        req->errmsg = "failed to parse existing config";
        goto DONE;
    }
    FREE(cfg_buf);

    // attempt to update CA bundle external to config file
    if (req->new_ca && strncmp(cfg.id.ca, "file://", strlen("file://")) == 0) {
        struct tlsuv_url_s path_uri;
        char path[FILENAME_MAX];
        CHECK_UV("parse CA bundle path", tlsuv_parse_url(&path_uri, cfg.id.ca));
        strncpy(path, path_uri.path, path_uri.path_len);
        CHECK_UV("update CA bundle file", update_file(path, req->new_ca, strlen(req->new_ca)));
        FREE(req->new_ca);
    }

    bool write_new_cfg = false;
    if (req->new_url) {
        free((char*)cfg.controller_url);
        cfg.controller_url = req->new_url;
        req->new_url = NULL;
        write_new_cfg = true;
    }

    if (req->new_ca) {
        free((char*)cfg.id.ca);
        cfg.id.ca = req->new_ca;
        req->new_ca = NULL;
        write_new_cfg = true;
    }

    if (write_new_cfg) {
        cfg_buf = ziti_config_to_json(&cfg, 0, &cfg_len);
        CHECK_UV("update config", update_file(config_file, cfg_buf, cfg_len));
    }
    DONE:
    free_ziti_config(&cfg);
    FREE(cfg_buf);
}

static void update_config_done(uv_work_t *wr, int err) {
    api_update_req *req = wr->data;
    if (req->err != 0) {
        ZITI_LOG(ERROR, "failed to update config file: %d(%s)", req->err, req->errmsg);
    } else {
        ZITI_LOG(ERROR, "updated config file with new URL");
    }
    free(req);
}

IMPL_ENUM(TunnelCommand, TUNNEL_COMMANDS)

IMPL_MODEL(tunnel_command, TUNNEL_CMD)
IMPL_MODEL(tunnel_result, TUNNEL_CMD_RES)
IMPL_MODEL(tunnel_load_identity, TNL_LOAD_IDENTITY)

IMPL_MODEL(tunnel_identity_info, TNL_IDENTITY_INFO)
IMPL_MODEL(tunnel_identity_lst, TNL_IDENTITY_LIST)
IMPL_MODEL(tunnel_on_off_identity, TNL_ON_OFF_IDENTITY)
IMPL_MODEL(tunnel_ziti_dump, TNL_ZITI_DUMP)
IMPL_MODEL(tunnel_identity_id, TNL_IDENTITY_ID)
IMPL_MODEL(tunnel_mfa_enrol_res, TNL_MFA_ENROL_RES)
IMPL_MODEL(tunnel_submit_mfa, TNL_SUBMIT_MFA)
IMPL_MODEL(tunnel_verify_mfa, TNL_VERIFY_MFA)
IMPL_MODEL(tunnel_remove_mfa, TNL_REMOVE_MFA)
IMPL_MODEL(tunnel_generate_mfa_codes, TNL_GENERATE_MFA_CODES)
IMPL_MODEL(tunnel_mfa_recovery_codes, TNL_MFA_RECOVERY_CODES)
IMPL_MODEL(tunnel_get_mfa_codes, TNL_GET_MFA_CODES)
IMPL_MODEL(tunnel_identity_metrics, TNL_IDENTITY_METRICS)
IMPL_MODEL(tunnel_status_change, TUNNEL_STATUS_CHANGE)

// ************** TUNNEL Events
IMPL_ENUM(TunnelEvent, TUNNEL_EVENTS)

IMPL_MODEL(base_event, BASE_EVENT_MODEL)
IMPL_MODEL(ziti_ctx_event, ZTX_EVENT_MODEL)
IMPL_MODEL(mfa_event, MFA_EVENT_MODEL)
IMPL_MODEL(service_event, ZTX_SVC_EVENT_MODEL)
IMPL_MODEL(api_event, ZTX_API_EVENT_MODEL)
IMPL_MODEL(tunnel_command_inline, TUNNEL_CMD_INLINE)

IMPL_MODEL(jwt_provider, EXT_JWT_PROVIDER)
IMPL_MODEL(ext_signer_event, EXT_SIGNER_EVENT_MODEL)

