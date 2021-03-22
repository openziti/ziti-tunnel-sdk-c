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

static struct cmd_ctx_s {
    ziti_tunnel_ctrl ctrl;
    tunneler_context tunnel_ctx;
    command_cb cb;
    uv_loop_t *loop;
} CMD_CTX;

struct ziti_instance_s {
    ziti_options opts;
    command_cb load_cb;
    void *load_ctx;

    ziti_context ztx;
    LIST_ENTRY(ziti_instance_s) _next;
};

// temporary list to pass info between parse and run
static LIST_HEAD(instance_list, ziti_instance_s) instance_init_list;

// map<path -> ziti_instance>
static model_map instances;

static void on_ziti_event(ziti_context ztx, const ziti_event_t *event);

static const char * cfg_types[] = { "ziti-tunneler-client.v1", "intercept.v1", "ziti-tunneler-server.v1", "host.v1", NULL };

static long refresh_interval = 10;

static int process_cmd(const tunnel_comand *cmd, void (*cb)(const tunnel_result *, void *ctx), void *ctx);
static int load_identity(const char *path, command_cb cb, void *ctx);
static struct ziti_instance_s *new_ziti_instance(const char *path);
static void load_ziti_async(uv_async_t *ar);

const ziti_tunnel_ctrl* ziti_tunnel_init_cmd(uv_loop_t *loop, tunneler_context tunnel_ctx, command_cb cb) {
    CMD_CTX.loop = loop;
    CMD_CTX.tunnel_ctx = tunnel_ctx;
    CMD_CTX.cb = cb;
    CMD_CTX.ctrl.process = process_cmd;
    CMD_CTX.ctrl.load_identity = load_identity;
    return &CMD_CTX.ctrl;
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
            load_identity(load.path, cb, ctx);
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

        default: result.error = "command not implemented";
    }

    cb(&result, ctx);
    return 0;
}

static int load_identity(const char *path, command_cb cb, void *ctx) {

    struct ziti_instance_s *inst = new_ziti_instance(path);
    inst->load_cb = cb;
    inst->load_ctx = ctx;
    inst->opts.config = strdup(path);

    uv_async_t *ar = calloc(1, sizeof(uv_async_t));
    ar->data = inst;
    uv_async_init(CMD_CTX.loop, ar, load_ziti_async);
    uv_async_send(ar);
    return 0;
}

static struct ziti_instance_s *new_ziti_instance(const char *path) {
    struct ziti_instance_s *inst = calloc(1, sizeof(struct ziti_instance_s));
    inst->opts.config = realpath(path, NULL);
    inst->opts.config_types = cfg_types;
    inst->opts.events = ZitiContextEvent|ZitiServiceEvent;
    inst->opts.event_cb = on_ziti_event;
    inst->opts.refresh_interval = refresh_interval; /* default refresh */
    inst->opts.app_ctx = inst;
    return inst;
}

/** callback from ziti SDK when a new service becomes available to our identity */
static void on_service(ziti_context ziti_ctx, ziti_service *service, int status, void *tnlr_ctx) {
    ZITI_LOG(DEBUG, "service[%s]", service->name);
    tunneled_service_t *ts = ziti_sdk_c_on_service(ziti_ctx, service, status, tnlr_ctx);
    if (ts->intercept != NULL) {
        protocol_t *proto;
        STAILQ_FOREACH(proto, &ts->intercept->protocols, entries) {
            address_t *address;
            STAILQ_FOREACH(address, &ts->intercept->addresses, entries) {
                port_range_t *pr;
                STAILQ_FOREACH(pr, &ts->intercept->port_ranges, entries) {
                    ZITI_LOG(INFO, "intercepting address[%s:%s:%s] service[%s]",
                             proto->protocol, address->str, pr->str, service->name);
                }
            }
        }

    }
    if (ts->host != NULL) {
        ZITI_LOG(INFO, "hosting server_address[%s] service[%s]", ts->host->address, service->name);
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
        case ZitiContextEvent:
            if (event->event.ctx.ctrl_status == ZITI_OK) {
                ZITI_LOG(INFO, "ziti_ctx[%s] connected to controller", ziti_get_identity(ztx)->name);
            } else {
                ZITI_LOG(WARN, "ziti_ctx controller connections failed: %s", ziti_errorstr(event->event.ctx.ctrl_status));
            }
            break;

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
    if (model_map_get(&instances, config_path) != NULL) {
        ZITI_LOG(WARN, "ziti context already loaded for %s", inst->opts.config);
        result.success = false;
        result.error = "context already loaded";
    } else {
        ZITI_LOG(INFO, "loading ziti instance from %s", config_path);
        inst->opts.app_ctx = inst;
        if (ziti_init_opts(&inst->opts, ar->loop) == ZITI_OK) {
            model_map_set(&instances, config_path, inst);
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

IMPL_ENUM(TunnelCommand, TUNNEL_COMMANDS)

IMPL_MODEL(tunnel_comand, TUNNEL_CMD)
IMPL_MODEL(tunnel_result, TUNNEL_CMD_RES)
IMPL_MODEL(tunnel_load_identity, TNL_LOAD_IDENTITY)

IMPL_MODEL(tunnel_identity_info, TNL_IDENTITY_INFO)
IMPL_MODEL(tunnel_identity_list, TNL_IDENTITY_LIST)
