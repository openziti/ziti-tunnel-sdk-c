/*
Copyright 2019 Netfoundry, Inc.

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

#include "ziti_instance.h"
#include "stdarg.h"
#include <time.h>

#ifndef MAXBUFFERLEN
#define MAXBUFFERLEN 8192
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
static struct ziti_instance_s *new_ziti_instance(const char *identifier, const char *path);
static void load_ziti_async(uv_async_t *ar);
static void on_sigdump(uv_signal_t *sig, int signum);
static void on_mfa_query(ziti_context ztx, void* mfa_ctx, ziti_auth_query_mfa *aq_mfa, ziti_ar_mfa_cb response_cb);
static void submit_mfa(struct mfa_request_s *req, const char *code);
static ziti_context get_ziti(const char *identifier);

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

        case TunnelCommand_ZitiDump: {
            #ifndef MAXPATHLEN
            #define MAXPATHLEN 1024
            #endif
            ZITI_LOG(INFO, "ziti dump started ");
            tunnel_ziti_dump dump;
            if (cmd->data != NULL && parse_tunnel_ziti_dump(&dump, cmd->data, strlen(cmd->data)) != 0) {
                result.success = false;
                result.error = "invalid command";
                break;
            }
            const char *key;
            struct ziti_instance_s *inst;
            MODEL_MAP_FOREACH(key, inst, &instances) {
                const ziti_identity *identity = ziti_get_identity(inst->ztx);
                if (dump.id != NULL && strcmp(dump.id, identity->name) != 0) {
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
            ZITI_LOG(INFO, "ziti dump finished ");
            break;
        }

        default: result.error = "command not implemented";
        case TunnelCommand_SubmitMFA: {
            tunnel_submit_mfa auth = {0};
            if (cmd->data == NULL || parse_tunnel_submit_mfa(&auth, cmd->data, strlen(cmd->data)) != 0) {
                result.error = "invalid command";
                result.success = false;
                break;
            }

            struct ziti_instance_s *inst = model_map_get(&instances, auth.identifier);
            if (inst == NULL) {
                result.error = "ziti context not found";
                result.success = false;
                break;
            }

            if (inst->mfa_req == NULL) {
                result.error = "no active MFA auth request";
                result.success = false;
                break;
            }

            inst->mfa_req->cmd_cb = cb;
            inst->mfa_req->cmd_ctx = ctx;

            submit_mfa(inst->mfa_req, auth.code);
            free_tunnel_submit_mfa(&auth);
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

#if _WIN32
#define realpath(rel, abs) _fullpath(abs, rel, MAX_PATH)
#endif

static struct ziti_instance_s *new_ziti_instance(const char *identifier, const char *path) {
    struct ziti_instance_s *inst = calloc(1, sizeof(struct ziti_instance_s));
    inst->identifier = strdup(identifier ? identifier : path);
    inst->opts.config = realpath(path, NULL);
    inst->opts.config_types = cfg_types;
    inst->opts.events = ZitiContextEvent|ZitiServiceEvent;
    inst->opts.event_cb = on_ziti_event;
    inst->opts.refresh_interval = refresh_interval; /* default refresh */
    inst->opts.aq_mfa_cb = on_mfa_query;
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
            if (event->event.ctx.ctrl_status == ZITI_OK) {
                ZITI_LOG(INFO, "ziti_ctx[%s] connected to controller", ziti_get_identity(ztx)->name);
                ev.status = "OK";
            } else {
                ZITI_LOG(WARN, "ziti_ctx controller connections failed: %s", ziti_errorstr(event->event.ctx.ctrl_status));
                ev.status = (char*)ziti_errorstr(event->event.ctx.ctrl_status);
            }
            CMD_CTX.on_event((const base_event *) &ev);
            break;
        }

        case ZitiServiceEvent: {
            ziti_service **zs;
            for (zs = event->event.service.removed; *zs != NULL; zs++) {
                on_service(ztx, *zs, ZITI_SERVICE_UNAVAILABLE, CMD_CTX.tunnel_ctx);
            }
            for (zs = event->event.service.added; *zs != NULL; zs++) {
                on_service(ztx, *zs, ZITI_OK, CMD_CTX.tunnel_ctx);
            }
            for (zs = event->event.service.changed; *zs != NULL; zs++) {
                on_service(ztx, *zs, ZITI_OK, CMD_CTX.tunnel_ctx);
            }
            break;
        }

        case ZitiRouterEvent:
            break;
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

static void on_submit_mfa(ziti_context ztx, void *mfa_ctx, int status, void *ctx) {
    struct mfa_request_s *req = ctx;
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

    if (status == ZITI_OK) {
        struct ziti_instance_s *inst = ziti_app_ctx(ztx);
        inst->mfa_req = NULL;
        free(req);
    }
}

static void submit_mfa(struct mfa_request_s *req, const char *code) {
    req->submit_f(req->ztx, req->submit_ctx, (char*)code, on_submit_mfa, req);
}

static void on_sigdump(uv_signal_t *sig, int signum) {
#ifndef MAXPATHLEN
#define MAXPATHLEN 1024
#endif
    char fname[MAXPATHLEN];
    snprintf(fname, sizeof(fname), "/tmp/ziti-dump.%d.dump", getpid());
    ZITI_LOG(INFO, "saving Ziti dump to %s", fname);
    FILE *dumpfile = fopen(fname, "a+");

    uv_timeval64_t dump_time;
    uv_gettimeofday(&dump_time);

    char time_str[32];
    struct tm* start_tm = gmtime(&dump_time.tv_sec);
    strftime(time_str, sizeof(time_str), "%FT%T", start_tm);

    fprintf(dumpfile, "ZIti Dump starting: %s\n",time_str);
    const char *k;
    struct ziti_instance_s *inst;
    MODEL_MAP_FOREACH(k, inst, &instances) {
        fprintf(dumpfile, "instance: %s\n", k);
        ziti_dump(inst->ztx, (int (*)(void *, const char *, ...)) fprintf, dumpfile);
    }

    fflush(dumpfile);
    fclose(dumpfile);
}

IMPL_ENUM(TunnelCommand, TUNNEL_COMMANDS)

IMPL_MODEL(tunnel_comand, TUNNEL_CMD)
IMPL_MODEL(tunnel_result, TUNNEL_CMD_RES)
IMPL_MODEL(tunnel_load_identity, TNL_LOAD_IDENTITY)

IMPL_MODEL(tunnel_identity_info, TNL_IDENTITY_INFO)
IMPL_MODEL(tunnel_identity_list, TNL_IDENTITY_LIST)
IMPL_MODEL(tunnel_ziti_dump, TNL_ZITI_DUMP)
IMPL_MODEL(tunnel_submit_mfa, TNL_SUBMIT_MFA)

// ************** TUNNEL Events
IMPL_ENUM(TunnelEvent, TUNNEL_EVENTS)

IMPL_MODEL(base_event, BASE_EVENT_MODEL)
IMPL_MODEL(ziti_ctx_event, ZTX_EVENT_MODEL)
IMPL_MODEL(mfa_event, MFA_EVENT_MODEL)
