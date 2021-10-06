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

#include <ziti/ziti_tunnel_cbs.h>
#include <ziti/ziti_log.h>

#include "ziti_hosting.h"
#include "ziti_instance.h"
#include "stdarg.h"
#include <time.h>
#include <http_parser.h>

#ifndef MAXBUFFERLEN
#define MAXBUFFERLEN 8192
#endif

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 254
#endif

// temporary list to pass info between parse and run
// static LIST_HEAD(instance_list, ziti_instance_s) instance_init_list;

// map<path -> ziti_instance>
static model_map instances;

static void on_ziti_event(ziti_context ztx, const ziti_event_t *event);

static const char * cfg_types[] = { "ziti-tunneler-client.v1", "intercept.v1", "ziti-tunneler-server.v1", "host.v1", NULL };

static long refresh_interval = 10;

static int process_cmd(const tunnel_comand *cmd, void (*cb)(const tunnel_result *, void *ctx), void *ctx);
static int load_identity(const char *identifier, const char *path, command_cb cb, void *ctx);
static void get_transfer_rates(const char *identifier, transfer_rates_cb cb, void *ctx);
static struct ziti_instance_s *new_ziti_instance(const char *identifier, const char *path);
static void load_ziti_async(uv_async_t *ar);
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

struct tunnel_cb_s {
    void *ctx;
    command_cb cmd_cb;
    void *cmd_ctx;
};

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

IMPL_ENUM(mfa_status, MFA_STATUS)

static ziti_context get_ziti(const char *identifier) {
    struct ziti_instance_s *inst = model_map_get(&instances, identifier);

    return inst ? inst->ztx : NULL;
}

static int ziti_dump_to_log_op(void* stringsBuilder, const char *fmt,  ...) {
    static char line[4096];

    va_list vargs;
    va_start(vargs, fmt);
    vsnprintf(line, sizeof(line), fmt, vargs);
    va_end(vargs);

    if (strlen(stringsBuilder) + strlen(line) > MAXBUFFERLEN) {
        return -1;
    }
    // write/append to the buffer
    strncat(stringsBuilder, line, sizeof(line));
    return 0;
}

static void ziti_dump_to_log(void *ctx) {
    char* buffer;
    buffer = malloc(MAXBUFFERLEN*sizeof(char));
    buffer[0] = 0;
    //actually invoke ziti_dump here
    ziti_dump(ctx, ziti_dump_to_log_op, buffer);
    ZITI_LOG(INFO, "ziti dump to log %s", buffer);
    free(buffer);
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
    fp = fopen(outputFile, "a+");
    if(fp == NULL)
    {
        ZITI_LOG(ERROR, "ziti dump to file failed. Unable to Read / Write / Create File");
        return;
    }
    uv_timeval64_t dump_time;
    uv_gettimeofday(&dump_time);

    char time_str[32];
    struct tm* start_tm = gmtime(&dump_time.tv_sec);
    strftime(time_str, sizeof(time_str), "%FT%T", start_tm);

    fprintf(fp, "Ziti Dump starting: %s\n",time_str);

    //actually invoke ziti_dump here
    ziti_dump(ctx, ziti_dump_to_file_op, fp);
    fflush(fp);
    fclose(fp);
}

static void disconnect_identity(ziti_context ziti_ctx, void *tnlr_ctx) {
    ZITI_LOG(INFO, "Disconnecting Identity %s", ziti_get_identity(ziti_ctx)->name);
    remove_intercepts(ziti_ctx, tnlr_ctx);
    ziti_shutdown(ziti_ctx);
}


static int process_cmd(const tunnel_comand *cmd, command_cb cb, void *ctx) {
    tunnel_result result = {
            .success = false,
            .error = NULL,
            .data = NULL,
    };
    ZITI_LOG(INFO, "processing command[%s] with data[%s]", TunnelCommands.name(cmd->command), cmd->data);
    switch (cmd->command) {
        case TunnelCommand_LoadIdentity: {
            tunnel_load_identity load;
            if (cmd->data == NULL || parse_tunnel_load_identity(&load, cmd->data, strlen(cmd->data)) != 0) {
                result.success = false;
                result.error = "invalid command";
                break;
            }
            const char *id = load.identifier ? load.identifier : load.path;
            load_identity(id, load.path, cb, ctx);
            return 0;
        }

        case TunnelCommand_ListIdentities: {
            tunnel_identity_list id_list = {0};
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

            result.data = tunnel_identity_list_to_json(&id_list, MODEL_JSON_COMPACT, NULL);
            result.success = true;

            cb(&result, ctx);

            free_tunnel_identity_list(&id_list);
            free(result.data);
            return 0;
        }

        case TunnelCommand_DisableIdentity: {
            tunnel_disable_identity disable_id = {0};
            if (cmd->data == NULL || parse_tunnel_disable_identity(&disable_id, cmd->data, strlen(cmd->data)) != 0) {
                result.success = false;
                result.error = "invalid command";
                free_tunnel_disable_identity(&disable_id);
                break;
            }
            struct ziti_instance_s *inst = model_map_get(&instances, disable_id.path);
            if (inst == NULL) {
                result.error = "ziti context not found";
                result.success = false;
                free_tunnel_disable_identity(&disable_id);
                break;
            }
            if (inst) {
                disconnect_identity(inst->ztx, CMD_CTX.tunnel_ctx);
                model_map_remove(&instances, disable_id.path);
                result.success = true;
            } else {
                result.success = false;
                result.error = malloc(sizeof(disable_id.path) + 35);
                sprintf(result.error, "ziti instance for id %s is not found", disable_id.path);
            }

            cb(&result, ctx);
            free_tunnel_disable_identity(&disable_id);
            return 0;
        }

        case TunnelCommand_ZitiDump: {
            #ifndef MAXPATHLEN
            #define MAXPATHLEN 1024
            #endif
            ZITI_LOG(INFO, "ziti dump started ");
            tunnel_ziti_dump dump = {0};
            if (cmd->data != NULL && parse_tunnel_ziti_dump(&dump, cmd->data, strlen(cmd->data)) != 0) {
                result.success = false;
                result.error = "invalid command";
                free_tunnel_ziti_dump(&dump);
                break;
            }
            const char *key;
            struct ziti_instance_s *inst;
            MODEL_MAP_FOREACH(key, inst, &instances) {
                const ziti_identity *identity = ziti_get_identity(inst->ztx);
                if (dump.identifier != NULL && strcmp(dump.identifier, inst->identifier) != 0) {
                    continue;
                }
                if (dump.dump_path == NULL) {
                    ziti_dump_to_log(inst->ztx);
                } else {
                    char dump_file[MAXPATHLEN];
                    snprintf(dump_file, sizeof(dump_file), "%s/%s.ziti", dump.dump_path, identity->name);
                    ziti_dump_to_file(inst->ztx, dump_file);
                }
                result.success = true;
            }
            if (!result.success) {
                char errorMsg[1024];
                snprintf(errorMsg, sizeof(errorMsg),"No matching identifier found for %s", dump.identifier);
                result.error = errorMsg;
                ZITI_LOG(WARN, result.error);
            }
            ZITI_LOG(INFO, "ziti dump finished ");
            free_tunnel_ziti_dump(&dump);
            break;
        }

        case TunnelCommand_EnableMFA: {
            tunnel_enable_mfa enable_mfa_cmd = {0};
            if (cmd->data != NULL && parse_tunnel_enable_mfa(&enable_mfa_cmd, cmd->data, strlen(cmd->data)) != 0) {
                result.success = false;
                result.error = "invalid command";
                free_tunnel_enable_mfa(&enable_mfa_cmd);
                break;
            }

            struct ziti_instance_s *inst = model_map_get(&instances, enable_mfa_cmd.identifier);
            if (inst == NULL) {
                result.error = "ziti context not found";
                result.success = false;
                free_tunnel_enable_mfa(&enable_mfa_cmd);
                break;
            }
            if (inst->ztx == NULL) {
                result.error = "ziti context is not loaded";
                result.success = false;
                break;
            }

            struct tunnel_cb_s *req = malloc(sizeof(struct tunnel_cb_s));
            req->ctx = strdup(enable_mfa_cmd.identifier);
            req->cmd_cb = cb;
            req->cmd_ctx = ctx;

            enable_mfa(inst->ztx, req);

            free_tunnel_enable_mfa(&enable_mfa_cmd);
            return 0;
        }

        case TunnelCommand_VerifyMFA: {
            tunnel_verify_mfa verify_mfa_cmd = {0};
            if (cmd->data != NULL && parse_tunnel_verify_mfa(&verify_mfa_cmd, cmd->data, strlen(cmd->data)) != 0) {
                result.success = false;
                result.error = "invalid command";
                free_tunnel_verify_mfa(&verify_mfa_cmd);
                break;
            }

            struct ziti_instance_s *inst = model_map_get(&instances, verify_mfa_cmd.identifier);
            if (inst == NULL) {
                result.error = "ziti context not found";
                result.success = false;
                free_tunnel_verify_mfa(&verify_mfa_cmd);
                break;
            }
            if (inst->ztx == NULL) {
                result.error = "ziti context is not loaded";
                result.success = false;
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
            if (cmd->data != NULL && parse_tunnel_remove_mfa(&remove_mfa_cmd, cmd->data, strlen(cmd->data)) != 0) {
                result.success = false;
                result.error = "invalid command";
                free_tunnel_remove_mfa(&remove_mfa_cmd);
                break;
            }

            struct ziti_instance_s *inst = model_map_get(&instances, remove_mfa_cmd.identifier);
            if (inst == NULL) {
                result.error = "ziti context not found";
                result.success = false;
                free_tunnel_remove_mfa(&remove_mfa_cmd);
                break;
            }
            if (inst->ztx == NULL) {
                result.error = "ziti context is not loaded";
                result.success = false;
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

        default: result.error = "command not implemented";
        case TunnelCommand_SubmitMFA: {
            tunnel_submit_mfa auth = {0};
            if (cmd->data == NULL || parse_tunnel_submit_mfa(&auth, cmd->data, strlen(cmd->data)) != 0) {
                result.error = "invalid command";
                result.success = false;
                free_tunnel_submit_mfa(&auth);
                break;
            }

            struct ziti_instance_s *inst = model_map_get(&instances, auth.identifier);
            if (inst == NULL) {
                result.error = "ziti context not found";
                result.success = false;
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
            if (cmd->data == NULL || parse_tunnel_generate_mfa_codes(&generate_mfa_codes_cmd, cmd->data, strlen(cmd->data)) != 0) {
                result.error = "invalid command";
                result.success = false;
                free_tunnel_generate_mfa_codes(&generate_mfa_codes_cmd);
                break;
            }

            struct ziti_instance_s *inst = model_map_get(&instances, generate_mfa_codes_cmd.identifier);
            if (inst == NULL) {
                result.error = "ziti context not found";
                result.success = false;
                free_tunnel_generate_mfa_codes(&generate_mfa_codes_cmd);
                break;
            }
            if (inst->ztx == NULL) {
                result.error = "ziti context is not loaded";
                result.success = false;
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
            if (cmd->data == NULL || parse_tunnel_get_mfa_codes(&get_mfa_codes_cmd, cmd->data, strlen(cmd->data)) != 0) {
                result.error = "invalid command";
                result.success = false;
                break;
            }

            struct ziti_instance_s *inst = model_map_get(&instances, get_mfa_codes_cmd.identifier);
            if (inst == NULL) {
                result.error = "ziti context not found";
                result.success = false;
                break;
            }
            if (inst->ztx == NULL) {
                result.error = "ziti context is not loaded";
                result.success = false;
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
            tunnel_get_identity_metrics get_identity_metrics_cmd = {0};
            if (cmd->data == NULL || parse_tunnel_get_identity_metrics(&get_identity_metrics_cmd, cmd->data, strlen(cmd->data)) != 0) {
                result.error = "invalid command";
                result.success = false;
                break;
            }

            struct ziti_instance_s *inst = model_map_get(&instances, get_identity_metrics_cmd.identifier);
            if (inst == NULL) {
                result.error = "ziti context not found";
                result.success = false;
                break;
            }

            get_transfer_rates(strdup(get_identity_metrics_cmd.identifier), cb, ctx);
            free_tunnel_get_identity_metrics(&get_identity_metrics_cmd);
            return 0;
        }

        case TunnelCommand_Unknown:
            break;
    }

    cb(&result, ctx);
    return 0;
}

static int load_identity(const char *identifier, const char *path, command_cb cb, void *ctx) {

    struct ziti_instance_s *inst = new_ziti_instance(identifier, path);
    inst->load_cb = cb;
    inst->load_ctx = ctx;
    inst->opts.config = strdup(path);

    uv_async_t *ar = calloc(1, sizeof(uv_async_t));
    ar->data = inst;
    uv_async_init(CMD_CTX.loop, ar, load_ziti_async);
    uv_async_send(ar);
    return 0;
}

static void get_transfer_rates(const char *identifier, transfer_rates_cb cb, void *ctx) {
    struct ziti_instance_s *inst = model_map_get(&instances, identifier);
    double up, down;
    ziti_get_transfer_rates(inst->ztx, &up, &down);
    tunnel_identity_metrics *id_metrics = calloc(1, sizeof(struct tunnel_identity_metrics_s));
    id_metrics->identifier = strdup(identifier);
    int metrics_len = 6;
    if (up > 0) {
        id_metrics->up = malloc((metrics_len + 1) * sizeof(char));
        snprintf(id_metrics->up, metrics_len, "%.2lf", up);
    }
    if (down > 0) {
        id_metrics->down = malloc((metrics_len + 1) * sizeof(char));
        snprintf(id_metrics->down, metrics_len, "%.2lf", down);
    }

    tunnel_result *result = calloc(1, sizeof(tunnel_result));
    result->success = true;
    size_t json_len;
    char *json = tunnel_identity_metrics_to_json(id_metrics, MODEL_JSON_COMPACT, &json_len);
    result->data = calloc(json_len, sizeof(char));
    result->data = json;
    free_tunnel_identity_metrics(id_metrics);
    cb(result, ctx);

}

#if _WIN32
#define realpath(rel, abs) _fullpath(abs, rel, MAX_PATH)
#endif

static struct ziti_instance_s *new_ziti_instance(const char *identifier, const char *path) {
    struct ziti_instance_s *inst = calloc(1, sizeof(struct ziti_instance_s));
    inst->identifier = strdup(identifier ? identifier : path);
    inst->opts.config = realpath(path, NULL);
    inst->opts.config_types = cfg_types;
    inst->opts.events = ZitiContextEvent|ZitiServiceEvent|ZitiRouterEvent|ZitiMfaAuthEvent;
    inst->opts.event_cb = on_ziti_event;
    inst->opts.refresh_interval = refresh_interval; /* default refresh */
    //inst->opts.aq_mfa_cb = on_mfa_query;
    inst->opts.app_ctx = inst;
    return inst;
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

    switch (event->type) {
        case ZitiContextEvent: {
            ziti_ctx_event ev = {0};
            ev.event_type = TunnelEvents.ContextEvent;
            ev.identifier = instance->identifier;
            ev.code = event->event.ctx.ctrl_status;
            if (event->event.ctx.ctrl_status == ZITI_OK) {
                ev.name = ziti_get_identity(ztx)->name;
                ev.version = ziti_get_controller_version(ztx)->version;
                ev.controller = instance->opts.controller;
                ZITI_LOG(INFO, "ziti_ctx[%s] connected to controller", ziti_get_identity(ztx)->name);
                ev.status = "OK";
                const char *ctrl = ziti_get_controller(ztx);
                struct http_parser_url ctrl_url;
                if (http_parser_parse_url(ctrl, strlen(ctrl), 0, &ctrl_url) == 0 && (ctrl_url.field_set & UF_HOST)) {
                    char ctrl_hostname[HOST_NAME_MAX];
                    snprintf(ctrl_hostname, sizeof(ctrl_hostname), "%.*s", ctrl_url.field_data[UF_HOST].len, ctrl + ctrl_url.field_data[UF_HOST].off);
                    ziti_tunneler_exclude_route(CMD_CTX.tunnel_ctx, ctrl_hostname);
                } else {
                    ZITI_LOG(WARN, "failed to parse controller URL(%s)", ctrl);
                }

            } else {
                ZITI_LOG(WARN, "ziti_ctx controller connections failed: %s", ziti_errorstr(event->event.ctx.ctrl_status));
                ev.status = (char*)ziti_errorstr(event->event.ctx.ctrl_status);
            }
            CMD_CTX.on_event((const base_event *) &ev);
            break;
        }

        case ZitiServiceEvent: {
            ziti_service **zs;
            service_event ev = {0};
            if (*event->event.service.removed != NULL) {
                ev.removed_services = event->event.service.removed;
            }
            for (zs = event->event.service.removed; *zs != NULL; zs++) {
                on_service(ztx, *zs, ZITI_SERVICE_UNAVAILABLE, CMD_CTX.tunnel_ctx);
            }

            if (*event->event.service.added != NULL) {
                ev.added_services = event->event.service.added;
            }
            for (zs = event->event.service.added; *zs != NULL; zs++) {
                on_service(ztx, *zs, ZITI_OK, CMD_CTX.tunnel_ctx);
            }

            if (*event->event.service.changed != NULL) {
                ev.added_services = event->event.service.changed;
                ev.removed_services = event->event.service.changed;
            }
            for (zs = event->event.service.changed; *zs != NULL; zs++) {
                on_service(ztx, *zs, ZITI_OK, CMD_CTX.tunnel_ctx);
            }

            ev.event_type = TunnelEvents.ServiceEvent;
            ev.identifier = instance->identifier;
            CMD_CTX.on_event((const base_event *) &ev);
            break;
        }

        case ZitiRouterEvent: {
            const struct ziti_router_event *rt_event = &event->event.router;
            const char *ctx_name = ziti_get_identity(ztx)->name;
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

        case ZitiMfaAuthEvent : {
            const char *ctx_name = ziti_get_identity(ztx)->name;
            ZITI_LOG(INFO, "ztx[%s] Mfa event received", ctx_name);
            mfa_event ev = {0};
            ev.event_type = TunnelEvents.MFAEvent;
            ev.identifier = instance->identifier;
            CMD_CTX.on_event((const base_event *) &ev);
        }
    }
}

static void load_ziti_async(uv_async_t *ar) {
    struct ziti_instance_s *inst = ar->data;

    tunnel_result result = {
            .success = true,
            .error = NULL,
    };

    char *config_path = realpath(inst->opts.config, NULL);
    ZITI_LOG(INFO, "attempting to load ziti instance from file[%s]", inst->opts.config);
    if (model_map_get(&instances, inst->identifier) != NULL) {
        ZITI_LOG(WARN, "ziti context already loaded for %s", inst->opts.config);
        result.success = false;
        result.error = "context already loaded";
    } else {
        ZITI_LOG(INFO, "loading ziti instance from %s", config_path);
        inst->opts.app_ctx = inst;
        if (ziti_init_opts(&inst->opts, ar->loop) == ZITI_OK) {
            model_map_set(&instances, inst->identifier, inst);
        } else {
            result.success = false;
            result.error = "failed to initialize ziti";
        }
    }

    inst->load_cb(&result, inst->load_ctx);
    inst->load_ctx = NULL;
    inst->load_cb = NULL;

    if (!result.success) {
        free(inst);
    }

    free(config_path);
    uv_close((uv_handle_t *) ar, (uv_close_cb) free);
}

/*
static void on_mfa_query(ziti_context ztx, void* mfa_ctx, ziti_auth_query_mfa *aq_mfa, ziti_ar_mfa_cb response_cb) {
    struct ziti_instance_s *inst = ziti_app_ctx(ztx);

    struct mfa_request_s *mfar = calloc(1, sizeof(struct mfa_request_s));
    mfar->ztx = ztx;
    mfar->submit_f = response_cb;
    mfar->submit_ctx = mfa_ctx;

    inst->mfa_req = mfar;

    mfa_event ev = {0};
    ev.event_type = TunnelEvents.MFAEvent;
    ev.provider = strdup(aq_mfa->provider);
    ev.identifier = strdup(inst->identifier);

    CMD_CTX.on_event((const base_event *) &ev);

    free_mfa_event(&ev);
}
 */

static void on_submit_mfa(ziti_context ztx, int status, void *ctx) {
    struct tunnel_cb_s *req = ctx;
    tunnel_result result = {0};
    if (status != ZITI_OK) {
        result.success = false;
        result.error = (char*)ziti_errorstr(status);
    } else {
        result.success = true;
    }

    if (req->cmd_cb) {
        req->cmd_cb(&result, req->cmd_ctx);
    }

    struct ziti_instance_s *inst = ziti_app_ctx(ztx);
    mfa_event *ev = calloc(1, sizeof(struct mfa_event_s));
    ev->operation = strdup(mfa_status_name(mfa_status_mfa_auth_status));
    ev->operation_type = mfa_status_mfa_auth_status;
    tunnel_status_event(TunnelEvent_MFAStatusEvent, status, ev, inst);

    if (status == ZITI_OK) {
        inst->mfa_req = NULL;
    }
    free(req);
}

static void submit_mfa(ziti_context ztx, const char *code, void *ctx) {
    ziti_mfa_auth(ztx, code, on_submit_mfa, ctx);
}

static void on_enable_mfa(ziti_context ztx, int status, ziti_mfa_enrollment *enrollment, void *ctx) {
    // send the response from enroll mfa to client
    struct tunnel_cb_s *req = ctx;
    tunnel_result result = {0};
    if (status != ZITI_OK) {
        result.success = false;
        result.error = (char*)ziti_errorstr(status);
    } else {
        result.success = true;

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
    mfa_event *ev = calloc(1, sizeof(struct mfa_event_s));
    ev->operation = strdup(mfa_status_name(mfa_status_enrollment_challenge));
    ev->operation_type = mfa_status_enrollment_challenge;
    ev->provisioning_url = strdup(enrollment->provisioning_url);
    char **rc = enrollment->recovery_codes;
    int code_len = 0;
    while (*rc != NULL) {
        code_len = code_len + strlen(*rc);
        rc++;
    }
    ev->recovery_codes = malloc(code_len + 1);
    int idx;
    for (idx=0; enrollment->recovery_codes[idx] !=0; idx++) {
        ev->recovery_codes[idx] = calloc(strlen(enrollment->recovery_codes[idx]), sizeof(char));
        ev->recovery_codes[idx] = enrollment->recovery_codes[idx];
    }
    ev->recovery_codes[idx] = '\0';
    tunnel_status_event(TunnelEvent_MFAStatusEvent, status, ev, inst);

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
    } else {
        result.success = true;
    }
    if (req->cmd_cb) {
        req->cmd_cb(&result, req->cmd_ctx);
    }

    struct ziti_instance_s *inst = ziti_app_ctx(ztx);
    mfa_event *ev = calloc(1, sizeof(struct mfa_event_s));
    ev->operation = strdup(mfa_status_name(mfa_status_enrollment_verification));
    ev->operation_type = mfa_status_enrollment_verification;
    tunnel_status_event(TunnelEvent_MFAStatusEvent, status, ev, inst);

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
    } else {
        result.success = true;
    }
    if (req->cmd_cb) {
        req->cmd_cb(&result, req->cmd_ctx);
    }

    struct ziti_instance_s *inst = ziti_app_ctx(ztx);
    mfa_event *ev = calloc(1, sizeof(struct mfa_event_s));
    ev->operation = strdup(mfa_status_name(mfa_status_enrollment_remove));
    ev->operation_type = mfa_status_enrollment_remove;
    tunnel_status_event(TunnelEvent_MFAStatusEvent, status, ev, inst);

    free(req);
}

static void remove_mfa(ziti_context ztx, char *code, void *ctx) {
    ziti_mfa_remove(ztx, code, on_remove_mfa, ctx);
}

static void on_mfa_recovery_codes(ziti_context ztx, int status, char **recovery_codes, void *ctx) {
    struct tunnel_cb_s *req = ctx;
    tunnel_result result = {0};
    if (status != ZITI_OK) {
        result.success = false;
        result.error = (char*)ziti_errorstr(status);
    } else {
        result.success = true;

        tunnel_mfa_recovery_codes mfa_recovery_codes = {0};
        mfa_recovery_codes.identifier = req->ctx;
        mfa_recovery_codes.recovery_codes = recovery_codes;

        size_t json_len;
        result.data = tunnel_mfa_recovery_codes_to_json(&mfa_recovery_codes, MODEL_JSON_COMPACT, &json_len);
    }
    if (req->cmd_cb) {
        req->cmd_cb(&result, req->cmd_ctx);
    }
    free(req);
}

static void generate_mfa_codes(ziti_context ztx, char *code, void *ctx) {
    ziti_mfa_new_recovery_codes(ztx, code, on_mfa_recovery_codes, ctx);
}

static void get_mfa_codes(ziti_context ztx, char *code, void *ctx) {
    ziti_mfa_get_recovery_codes(ztx, code, on_mfa_recovery_codes, ctx);
}

#define CHECK(lbl, op) do{ \
int rc = (op);                  \
if (rc < 0) {              \
ZITI_LOG(ERROR, "operation[" #op "] failed: %d(%s) errno=%d", rc, strerror(rc), errno); \
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
    struct tm* start_tm = gmtime(&dump_time.tv_sec);
    strftime(time_str, sizeof(time_str), "%FT%T", start_tm);

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

IMPL_ENUM(TunnelCommand, TUNNEL_COMMANDS)

IMPL_MODEL(tunnel_comand, TUNNEL_CMD)
IMPL_MODEL(tunnel_result, TUNNEL_CMD_RES)
IMPL_MODEL(tunnel_load_identity, TNL_LOAD_IDENTITY)

IMPL_MODEL(tunnel_identity_info, TNL_IDENTITY_INFO)
IMPL_MODEL(tunnel_identity_list, TNL_IDENTITY_LIST)
IMPL_MODEL(tunnel_disable_identity, TNL_DISABLE_IDENTITY)
IMPL_MODEL(tunnel_ziti_dump, TNL_ZITI_DUMP)
IMPL_MODEL(tunnel_enable_mfa, TNL_ENABLE_MFA)
IMPL_MODEL(tunnel_mfa_enrol_res, TNL_MFA_ENROL_RES)
IMPL_MODEL(tunnel_submit_mfa, TNL_SUBMIT_MFA)
IMPL_MODEL(tunnel_verify_mfa, TNL_VERIFY_MFA)
IMPL_MODEL(tunnel_remove_mfa, TNL_REMOVE_MFA)
IMPL_MODEL(tunnel_generate_mfa_codes, TNL_GENERATE_MFA_CODES)
IMPL_MODEL(tunnel_mfa_recovery_codes, TNL_MFA_RECOVERY_CODES)
IMPL_MODEL(tunnel_get_mfa_codes, TNL_GET_MFA_CODES)
IMPL_MODEL(tunnel_get_identity_metrics, TNL_GET_IDENTITY_METRICS)
IMPL_MODEL(tunnel_identity_metrics, TNL_IDENTITY_METRICS)

// ************** TUNNEL Events
IMPL_ENUM(TunnelEvent, TUNNEL_EVENTS)

IMPL_MODEL(base_event, BASE_EVENT_MODEL)
IMPL_MODEL(ziti_ctx_event, ZTX_EVENT_MODEL)
IMPL_MODEL(mfa_event, MFA_EVENT_MODEL)
IMPL_MODEL(tunnel_command_inline, TUNNEL_CMD_INLINE)

