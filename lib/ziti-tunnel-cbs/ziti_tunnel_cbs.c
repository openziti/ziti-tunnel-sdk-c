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

#if _WIN32
// _WIN32_WINNT needs to be declared and needs to be > 0x600 in order for 
// some constants used below to be declared
#define _WIN32_WINNT  _WIN32_WINNT_WIN6
 // Windows Server 2008
#include <ws2tcpip.h>
#ifndef strcasecmp
#define strcasecmp(a,b) stricmp(a,b)
#endif
#endif

#include <stdio.h>
#include <ziti/ziti_log.h>
#include <memory.h>
#include <ziti/ziti_dns.h>
#include "ziti/ziti_tunnel_cbs.h"
#include "ziti_instance.h"
#include "ziti_hosting.h"

typedef int (*cfg_parse_fn)(void *, const char *, size_t);
typedef void* (*cfg_alloc_fn)();
typedef void (*cfg_free_fn)(void *);
typedef int (*cfg_cmp_fn)(const void *, const void*);

IMPL_ENUM(TunnelConnectionType, TUNNELER_CONN_TYPE_ENUM)
IMPL_MODEL(tunneler_app_data, TUNNELER_APP_DATA_MODEL)

static void ziti_conn_close_cb(ziti_connection zc);

typedef struct cfgtype_desc_s {
    const char *name;
    cfg_type_e cfgtype;
    cfg_alloc_fn alloc;
    cfg_free_fn free;
    cfg_parse_fn parse;
    cfg_cmp_fn compare;
} cfgtype_desc_t;

struct ziti_intercept_s {
    char *service_name;
    ziti_context ztx;
    struct cfgtype_desc_s *cfg_desc;
    union {
        ziti_intercept_cfg_v1 intercept_v1;
        ziti_client_cfg_v1 client_v1;
    } cfg;
};

#define CFGTYPE_DESC(name, cfgtype, type) { (name), (cfgtype), \
(cfg_alloc_fn)alloc_##type,                                    \
(cfg_free_fn)free_##type,                                      \
(cfg_parse_fn)parse_##type,                                    \
(cfg_cmp_fn)cmp_##type,                                        \
}

static struct cfgtype_desc_s intercept_cfgtypes[] = {
        CFGTYPE_DESC("intercept.v1", INTERCEPT_CFG_V1, ziti_intercept_cfg_v1),
        CFGTYPE_DESC("ziti-tunneler-client.v1", CLIENT_CFG_V1, ziti_client_cfg_v1)
};

static struct cfgtype_desc_s host_cfgtypes[] = {
        CFGTYPE_DESC("host.v1", HOST_CFG_V1, ziti_host_cfg_v1),
        CFGTYPE_DESC("ziti-tunneler-server.v1", SERVER_CFG_V1, ziti_server_cfg_v1)
};

static void free_ziti_intercept(ziti_intercept_t *zi) {
    if (zi == NULL) return;
    free(zi->service_name);
    if (zi->cfg_desc) {
        zi->cfg_desc->free(&zi->cfg);
    }

    free(zi);
}


static void on_ziti_connect(ziti_connection conn, int status) {
    ZITI_LOG(VERBOSE, "on_ziti_connect status: %d", status);
    struct io_ctx_s *io = ziti_conn_data(conn);
    if (io == NULL) {
        ZITI_LOG(WARN, "null io. underlay connection possibly leaked. ziti_conn[%p] status[%d]", conn, status);
        ziti_close(conn, NULL);
        return;
    }
    if (status == ZITI_OK) {
        ziti_tunneler_dial_completed(io, true);
    } else {
        ZITI_LOG(ERROR, "ziti dial failed: %s", ziti_errorstr(status));
        ziti_close(conn, ziti_conn_close_cb);
    }
}

/** called by ziti SDK when ziti service has data for the client */
static ssize_t on_ziti_data(ziti_connection conn, uint8_t *data, ssize_t len) {
    struct io_ctx_s *io = ziti_conn_data(conn);
    ZITI_LOG(TRACE, "got %zd bytes from ziti", len);
    if (io == NULL) {
        ZITI_LOG(WARN, "null io. underlay connection possibly leaked. ziti_conn[%p] len[%zd]", conn, len);
        ziti_close(conn, NULL);
        return UV_ECONNABORTED;
    }
    ziti_io_context *ziti_io_ctx = io->ziti_io;
    if (len > 0) {
        ssize_t accepted = ziti_tunneler_write(io->tnlr_io, data, len);
        if (accepted < 0) {
            ZITI_LOG(ERROR, "failed to write to client");
            ziti_sdk_c_close(io->ziti_io);
        }
        return accepted;
    } else if (len == ZITI_EOF) {
        ZITI_LOG(DEBUG, "ziti connection sent EOF (ziti_eof=%d, tnlr_eof=%d)", ziti_io_ctx->ziti_eof, ziti_io_ctx->tnlr_eof);
        ziti_io_ctx->ziti_eof = true; /* no more data will come from this connection */
        if (ziti_io_ctx->tnlr_eof) /* both sides are done sending now, so close both */ {
            ziti_close(conn, ziti_conn_close_cb);
        } else {
            // this ziti conn can still receive but it will not send any more, so
            // we will not write to the client any more. send FIN to the client.
            // eventually the client will send FIN and the tsdk will call ziti_sdk_c_close_write.
            ziti_tunneler_close_write(io->tnlr_io);
        }
    } else if (len < 0) {
        ZITI_LOG(DEBUG, "ziti connection is closed due to [%zd](%s)", len, ziti_errorstr(len));
        ziti_close(conn, ziti_conn_close_cb);
    }
    return len;
}

/** called by tunneler SDK after a client connection is closed. also called from ziti_tunneler_stop_intercepting */
int ziti_sdk_c_close(void *io_ctx) {
    if (io_ctx == NULL) {
        ZITI_LOG(DEBUG, "null io_ctx");
        return 1;
    }
    ziti_io_context *ziti_io_ctx = io_ctx;
    ZITI_LOG(DEBUG, "closing ziti_conn tnlr_eof=%d, ziti_eof=%d", ziti_io_ctx->tnlr_eof, ziti_io_ctx->ziti_eof);
    ziti_close(ziti_io_ctx->ziti_conn, ziti_conn_close_cb);
    return 1;
}

/** called by tunneler SDK after a client sends FIN */
int ziti_sdk_c_close_write(void *io_ctx) {
    ziti_io_context *ziti_io_ctx = io_ctx;
    ZITI_LOG(DEBUG, "closing ziti_conn tnlr_eof=%d, ziti_eof=%d", ziti_io_ctx->tnlr_eof, ziti_io_ctx->ziti_eof);
    ziti_io_ctx->tnlr_eof = true;
    if (ziti_io_ctx->ziti_eof) { // both sides are now closed
        ZITI_LOG(DEBUG, "closing ziti_conn tnlr_eof=%d, ziti_eof=%d", ziti_io_ctx->tnlr_eof, ziti_io_ctx->ziti_eof);
        ziti_close(ziti_io_ctx->ziti_conn, ziti_conn_close_cb);
        return 1;
    }

    ZITI_LOG(DEBUG, "closing ziti_conn tnlr_eof=%d, ziti_eof=%d", ziti_io_ctx->tnlr_eof, ziti_io_ctx->ziti_eof);
    ziti_close_write(ziti_io_ctx->ziti_conn);
    return 0;
}

char *string_replace(char *source, size_t sourceSize, const char *substring, const char *with) {
    /* look for first occurrence */
    char *substring_source = strstr(source, substring);
    if (substring_source == NULL) {
        return NULL;
    }

    /* verify the replacement fits in _source_ */
    if (sourceSize < strlen(source) + (strlen(with) - strlen(substring)) + 1) {
        ZITI_LOG(DEBUG, "replacing %s with %s in %s - not enough space", substring, with, source);
        return NULL;
    }

    /* shift the portion of _source_ that will be to the right of the replacement into position.
     * memmove allows overlapping dest/src addresses
     */
    memmove(
            substring_source + strlen(with),
            substring_source + strlen(substring),
            strlen(substring_source) - strlen(substring) + 1
    );

    /* copy the replacement into place */
    memcpy(substring_source, with, strlen(with));
    return substring_source + strlen(with);
}

/** parse "proto:ip:port" */
static void parse_socket_address(const char *address, char **proto, char **ip, char **port) {
    if (proto != NULL) *proto = NULL;
    if (ip != NULL) *ip = NULL;
    if (port != NULL) *port = NULL;

    if (address != NULL) {
        const char *proto_sep = strchr(address, ':');
        if (proto_sep != NULL) {
            size_t proto_len = proto_sep - address + 1;
            *proto = malloc(proto_len);
            snprintf(*proto, proto_len, "%.*s", (int) (proto_sep - address), address);
        }

        const char *ip_start = proto_sep + 1;
        const char *ip_sep = strrchr(address, ':');
        if (ip_sep != NULL) {
            size_t ip_len = ip_sep - ip_start + 1;
            *ip = malloc(ip_len);
            snprintf(*ip, ip_len, "%.*s", (int) (ip_sep - ip_start), ip_start);
            *port = strdup(ip_sep + 1);
        }
    }
}

/** render app_data as string (json) */
static ssize_t get_app_data_json(char *buf, size_t bufsz, tunneler_io_context io, ziti_context ziti_ctx, const char *source_ip) {
    tunneler_app_data app_data = {0};

    const char *intercepted = get_intercepted_address(io);
    const char *client = get_client_address(io);
    char source_addr[64];

    if (intercepted != NULL) {
        parse_socket_address(intercepted, &app_data.dst_protocol, &app_data.dst_ip, &app_data.dst_port);
        if (app_data.dst_ip) {
            const char *dst_hostname = ziti_dns_reverse_lookup(app_data.dst_ip);
            if (dst_hostname) {
                app_data.dst_hostname = strdup(dst_hostname);
            }
        }
    }

    if (client != NULL) {
        parse_socket_address(client, &app_data.src_protocol, &app_data.src_ip, &app_data.src_port);
    }

    if (source_ip != NULL && *source_ip != 0) {
        const ziti_identity *zid = ziti_get_identity(ziti_ctx);
        strncpy(source_addr, source_ip, sizeof(source_addr));
        string_replace(source_addr, sizeof(source_addr), "$tunneler_id.name", zid->name);
        string_replace(source_addr, sizeof(source_addr), "$dst_ip", app_data.dst_ip);
        string_replace(source_addr, sizeof(source_addr), "$dst_port", app_data.dst_port);
        string_replace(source_addr, sizeof(source_addr), "$src_ip", app_data.src_ip);
        string_replace(source_addr, sizeof(source_addr), "$src_port", app_data.src_port);
        app_data.source_addr = source_addr;
    }

    ssize_t json_len = tunneler_app_data_to_json_r(&app_data, MODEL_JSON_COMPACT, buf, bufsz);

    // value points to stack buffer
    app_data.source_addr = NULL;
    free_tunneler_app_data(&app_data);

    return json_len;
}

static void dial_opts_from_client_cfg_v1(ziti_dial_opts *opts, const ziti_client_cfg_v1 *config) {
}

/** initialize dial options from a ziti_intercept_cfg_v1 */
static void dial_opts_from_intercept_cfg_v1(ziti_dial_opts *opts, const ziti_intercept_cfg_v1 *config) {
    //model_map dial_options_cfg = config->dial_options;
    tag *t = (tag *) model_map_get(&(config->dial_options), "identity");
    if (t != NULL) {
        if (t->type == tag_string) {
            opts->identity = t->string_value; // todo strdup? t->string_value is allocated in ziti_intercept_cfg_v1.
        } else {
            ZITI_LOG(WARN, "dial_options.identity has non-string type %d", t->type);
        }
    }

    t = (tag *)model_map_get(&(config->dial_options), "connect_timeout_seconds");
    if (t != NULL) {
        if (t->type == tag_number) {
            opts->connect_timeout_seconds = t->num_value;
        } else {
            ZITI_LOG(WARN, "dial_options.connect_timeout_seconds has non-numeric type %d", t->type);
        }
    }
}

/** called by tunneler SDK after a client connection is intercepted */
void * ziti_sdk_c_dial(const void *intercept_ctx, struct io_ctx_s *io) {
    if (intercept_ctx == NULL) {
        ZITI_LOG(WARN, "null intercept_ctx");
        return NULL;
    }
    const ziti_intercept_t *zi_ctx = intercept_ctx;
    ZITI_LOG(VERBOSE, "ziti_dial(name=%s)", zi_ctx->service_name);

    ziti_io_context *ziti_io_ctx = malloc(sizeof(struct ziti_io_ctx_s));
    if (ziti_io_ctx == NULL) {
        ZITI_LOG(ERROR, "failed to allocate io context");
        return NULL;
    }
    io->ziti_io = ziti_io_ctx;

    ziti_context ziti_ctx = zi_ctx->ztx;
    if (ziti_conn_init(ziti_ctx, &ziti_io_ctx->ziti_conn, io) != ZITI_OK) {
        ZITI_LOG(ERROR, "ziti_conn_init failed");
        free(ziti_io_ctx);
        return NULL;
    }

    ziti_dial_opts dial_opts;
    memset(&dial_opts, 0, sizeof(dial_opts));
    char app_data_json[256];
    const char *source_ip = NULL;

    switch (zi_ctx->cfg_desc->cfgtype) {
        case CLIENT_CFG_V1:
            dial_opts_from_client_cfg_v1(&dial_opts, &zi_ctx->cfg.client_v1);
            break;
        case INTERCEPT_CFG_V1:
            dial_opts_from_intercept_cfg_v1(&dial_opts, &zi_ctx->cfg.intercept_v1);
            source_ip = zi_ctx->cfg.intercept_v1.source_ip;
            break;
        default:
            break;
    }

    char resolved_dial_identity[128];
    if (dial_opts.identity != NULL && dial_opts.identity[0] != '\0') {
        const char *dst_addr = get_intercepted_address(io->tnlr_io);
        if (dst_addr != NULL) {
            char *proto, *ip, *port;
            strncpy(resolved_dial_identity, dial_opts.identity, sizeof(resolved_dial_identity));
            parse_socket_address(dst_addr, &proto, &ip, &port);
            if (proto != NULL) {
                string_replace(resolved_dial_identity, sizeof(resolved_dial_identity), "$dst_protocol", proto);
                free(proto);
            }
            if (ip != NULL) {
                string_replace(resolved_dial_identity, sizeof(resolved_dial_identity), "$dst_ip", ip);
                free(ip);
            }
            if (port != NULL) {
                string_replace(resolved_dial_identity, sizeof(resolved_dial_identity), "$dst_port", port);
                free(port);
            }
        }
        dial_opts.identity = resolved_dial_identity;
    }

    ssize_t json_len = get_app_data_json(app_data_json, sizeof(app_data_json), io->tnlr_io, ziti_ctx, source_ip);
    if (json_len < 0) {
        ZITI_LOG(ERROR, "service[%s] failed to encode app_data", zi_ctx->service_name);
        free(ziti_io_ctx);
        return NULL;
    }

    dial_opts.app_data_sz = (size_t) json_len;
    dial_opts.app_data = app_data_json;

    ZITI_LOG(DEBUG, "service[%s] app_data_json[%zd]='%.*s'", zi_ctx->service_name, dial_opts.app_data_sz, (int)dial_opts.app_data_sz, dial_opts.app_data);
    if (ziti_dial_with_options(ziti_io_ctx->ziti_conn, zi_ctx->service_name, &dial_opts, on_ziti_connect, on_ziti_data) != ZITI_OK) {
        ZITI_LOG(ERROR, "ziti_dial failed");
        free(ziti_io_ctx);
        return NULL;
    }

    ziti_io_ctx->ziti_eof = false;
    ziti_io_ctx->tnlr_eof = false;

    return ziti_io_ctx;
}

/** called by ziti SDK when data transfer initiated by ziti_write completes */
static void on_ziti_write(ziti_connection ziti_conn, ssize_t len, void *ctx) {
    if (len > 0) {
        ziti_tunneler_ack(ctx);
    }
}

/** called from tunneler SDK when intercepted client sends data */
ssize_t ziti_sdk_c_write(const void *ziti_io_ctx, void *write_ctx, const void *data, size_t len) {
    struct ziti_io_ctx_s *_ziti_io_ctx = (struct ziti_io_ctx_s *)ziti_io_ctx;
    int zs = ziti_write(_ziti_io_ctx->ziti_conn, (void *)data, len, on_ziti_write, write_ctx);
    if (zs != ZITI_OK) {
        ZITI_LOG(ERROR, "ziti_write(ziti_conn[%p]) failed: %s", _ziti_io_ctx->ziti_conn, ziti_errorstr(zs));
        on_ziti_write(_ziti_io_ctx->ziti_conn, len, write_ctx);
        ziti_close(_ziti_io_ctx->ziti_conn, ziti_conn_close_cb);
    }
    return zs;
}

ziti_intercept_t *new_ziti_intercept(ziti_context ztx, ziti_service *service, ziti_intercept_t *curr_i) {
    ziti_intercept_t *zi_ctx = calloc(1, sizeof(ziti_intercept_t));
    zi_ctx->ztx = ztx;
    zi_ctx->service_name = strdup(service->name);
    bool have_intercept = false;

    for (int i = 0; i < sizeof(intercept_cfgtypes) / sizeof(cfgtype_desc_t); i++) {
        cfgtype_desc_t *cfgtype = &intercept_cfgtypes[i];
        const char *cfg_json = ziti_service_get_raw_config(service, cfgtype->name);
        if (cfg_json != 0 && cfgtype->parse(&zi_ctx->cfg, cfg_json, strlen(cfg_json)) > 0) {
            zi_ctx->cfg_desc = cfgtype;

            if (curr_i && cfgtype == curr_i->cfg_desc && cfgtype->compare(&zi_ctx->cfg, &curr_i->cfg) == 0) {
                ZITI_LOG(DEBUG, "configuration[%s] was not changed for service[%s]", cfgtype->name, service->name);
            } else {
                ZITI_LOG(INFO, "%s intercept for service[%s] with %s = %s", curr_i ? "changing" : "creating", service->name, cfgtype->name, cfg_json);
                have_intercept = true;
            }

            break;
        }
    }

    if (!have_intercept) {
        free_ziti_intercept(zi_ctx);
        return NULL;
    }
    return zi_ctx;
}

// only do matching on based on wildcard domain here
static bool intercept_match_addr(ip_addr_t *addr, void *ctx) {
    ZITI_LOG(DEBUG, "matching %s", ipaddr_ntoa(addr));
    ziti_intercept_t *zi_ctx = ctx;
    if (zi_ctx->cfg_desc->cfgtype == INTERCEPT_CFG_V1) {
        ziti_intercept_cfg_v1 *cfg = &zi_ctx->cfg.intercept_v1;
        const char *domain = ziti_dns_reverse_lookup_domain(addr);
        if (domain) {
            for (int i = 0; cfg->addresses[i] != NULL; i++) {
                if (cfg->addresses[i]->type != ziti_address_hostname) continue;
                if (ziti_address_match_s(domain, cfg->addresses[i])) {
                    return true;
                }
            }
        }
    }
    return false;
}

static const ziti_address  *intercept_addr_from_cfg_addr(const ziti_address *cfg_addr, ziti_intercept_t *zi) {
    static ziti_address dns_addr;
    const ziti_address *intercept_addr_p = NULL;

    if (cfg_addr->type == ziti_address_cidr) {
        intercept_addr_p = cfg_addr;
    } else if (cfg_addr->type == ziti_address_hostname) {
        ip_addr_t *intercept_ip = ziti_dns_register_hostname(cfg_addr, zi);
        if (intercept_ip) {
            intercept_addr_p = &dns_addr;
            ziti_address_from_ip_addr(intercept_addr_p, intercept_ip);
        }
    } else {
        ZITI_LOG(WARN, "unknown ziti_address type %d", cfg_addr->type);
    }

    return intercept_addr_p;
}

intercept_ctx_t *new_intercept_ctx(tunneler_context tnlr_ctx, ziti_intercept_t *zi_ctx) {
    intercept_ctx_t *i_ctx = intercept_ctx_new(tnlr_ctx, zi_ctx->service_name, zi_ctx);
    intercept_ctx_set_match_addr(i_ctx, intercept_match_addr);

    int i;
    const ziti_address *intercept_addr;
    switch (zi_ctx->cfg_desc->cfgtype) {
        case CLIENT_CFG_V1:
            intercept_ctx_add_protocol(i_ctx, "udp");
            intercept_ctx_add_protocol(i_ctx, "tcp");
            intercept_addr = intercept_addr_from_cfg_addr(&zi_ctx->cfg.client_v1.hostname, zi_ctx);
            intercept_ctx_add_address(i_ctx, intercept_addr);
            intercept_ctx_add_port_range(i_ctx, zi_ctx->cfg.client_v1.port, zi_ctx->cfg.client_v1.port);
            break;
        case INTERCEPT_CFG_V1:
        {
            const ziti_intercept_cfg_v1 *config = &zi_ctx->cfg.intercept_v1;
            for (i = 0; config->protocols[i] != NULL; i++) {
                intercept_ctx_add_protocol(i_ctx, config->protocols[i]);
            }
            for (i = 0; config->addresses[i] != NULL; i++) {
                intercept_addr = intercept_addr_from_cfg_addr(config->addresses[i], zi_ctx);
                intercept_ctx_add_address(i_ctx, intercept_addr);
            }
            for (i = 0; config->port_ranges[i] != NULL; i++) {
                intercept_ctx_add_port_range(i_ctx, config->port_ranges[i]->low, config->port_ranges[i]->high);
            }
        }
            break;
        default:
            break;
    }

    return i_ctx;
}

static void stop_intercept(struct tunneler_ctx_s *tnlr, struct ziti_instance_s *inst, ziti_intercept_t *zi) {
    model_map_remove(&inst->intercepts, zi->service_name);
    ziti_dns_deregister_intercept(zi);
    ziti_tunneler_stop_intercepting(tnlr, zi);
    free_ziti_intercept(zi);
};

static tunneled_service_t current_tunneled_service;

/** set up intercept or host context according to service permissions and configuration */
tunneled_service_t *ziti_sdk_c_on_service(ziti_context ziti_ctx, ziti_service *service, int status, void *tnlr_ctx) {
    current_tunneled_service.intercept = NULL;
    current_tunneled_service.host = NULL;

    struct ziti_instance_s *ziti_instance = ziti_app_ctx(ziti_ctx);

    if (status == ZITI_OK) {
        int i, get_config_rc;
        cfgtype_desc_t *cfgtype;
        void *config;

        ziti_intercept_t *curr_i = model_map_get(&ziti_instance->intercepts, service->name);
        if ((service->perm_flags & ZITI_CAN_DIAL) == 0) {
            if (curr_i) {
                ZITI_LOG(DEBUG, "stopping intercept: can no longer dial service[%s]", service->name);
                stop_intercept(tnlr_ctx, ziti_instance, curr_i);
            }
        } else {
            ziti_intercept_t *zi_ctx = new_ziti_intercept(ziti_ctx, service, curr_i);

            if (zi_ctx) {
                if (curr_i) {
                    ZITI_LOG(DEBUG, "replacing intercept for service[%s]", service->name);
                    stop_intercept(tnlr_ctx, ziti_instance, curr_i);
                }

                model_map_set(&ziti_instance->intercepts, service->name, zi_ctx);
                intercept_ctx_t *i_ctx = new_intercept_ctx(tnlr_ctx, zi_ctx);
                ziti_tunneler_intercept(tnlr_ctx, i_ctx);
                current_tunneled_service.intercept = i_ctx;
            } else {
                if (curr_i)
                    current_tunneled_service.intercept = ziti_tunnel_find_intercept(tnlr_ctx, curr_i);
            }

            if (current_tunneled_service.intercept == NULL) {
                ZITI_LOG(DEBUG, "service[%s] can be dialed, but lacks intercept configuration; not intercepting", service->name);
            }
        }

        if (service->perm_flags & ZITI_CAN_BIND) {
            for (i = 0; i < sizeof(host_cfgtypes) / sizeof(cfgtype_desc_t); i++) {
                cfgtype = &host_cfgtypes[i];
                config = cfgtype->alloc();
                get_config_rc = ziti_service_get_config(service, cfgtype->name, config, cfgtype->parse);
                if (get_config_rc == 0) {
                    current_tunneled_service.host = ziti_tunneler_host(tnlr_ctx, ziti_ctx, service->name, cfgtype->cfgtype, config);
                    break;
                }
                cfgtype->free(config);
            }
            if (!current_tunneled_service.host) {
                ZITI_LOG(DEBUG, "service[%s] can be bound, but lacks host configuration; not hosting", service->name);
            }
        }
    } else if (status == ZITI_SERVICE_UNAVAILABLE) {
        ZITI_LOG(INFO, "service unavailable: %s", service->name);
        ziti_intercept_t *zi_ctx = model_map_remove(&ziti_instance->intercepts, service->name);
        if (zi_ctx) {
            stop_intercept(tnlr_ctx, ziti_instance, zi_ctx);
        }
    }

    return &current_tunneled_service;
}

void remove_intercepts(ziti_context ziti_ctx, void *tnlr_ctx) {

    struct ziti_instance_s *ziti_instance = ziti_app_ctx(ziti_ctx);

    model_map_iter it = model_map_iterator(&ziti_instance->intercepts);
    while(it) {
        ziti_intercept_t *zi_ctx = model_map_it_value(it);
        if (zi_ctx) {
            ziti_tunneler_stop_intercepting(tnlr_ctx, zi_ctx);
        }
        it = model_map_it_remove(it);
    }
}

/** called by ziti sdk after ziti_close completes */
static void ziti_conn_close_cb(ziti_connection zc) {
    ZITI_LOG(TRACE, "ziti_conn[%p] is closed", zc);
    struct io_ctx_s *io = ziti_conn_data(zc);
    if (io == NULL) {
        ZITI_LOG(WARN, "null io. underlay connection possibly leaked. ziti_conn[%p]", zc);
        return;
    }
    if (io->ziti_io) {
        free(io->ziti_io);
    }
    ziti_tunneler_close(io->tnlr_io);
    free(io);
    ziti_conn_set_data(zc, NULL);
    ZITI_LOG(VERBOSE, "nulled data for ziti_conn[%p]", zc);
}

#define RESOLVE_APP_DATA "{\"connType\":\"resolver\"}"
ziti_connection intercept_resolve_connect(ziti_intercept_t *intercept, void *ctx, ziti_conn_cb conn_cb, ziti_data_cb data_cb) {
    ziti_connection conn;
    ziti_conn_init(intercept->ztx, &conn, ctx);
    ziti_dial_opts opts = {
            .app_data = RESOLVE_APP_DATA,
            .app_data_sz = strlen(RESOLVE_APP_DATA)
    };

    ziti_dial_with_options(conn, intercept->service_name, &opts, conn_cb, data_cb);
    return conn;
}