#if _WIN32
// _WIN32_WINNT needs to be declared and needs to be > 0x600 in order for 
// some constants used below to be declared
#define _WIN32_WINNT  _WIN32_WINNT_WIN6
 // Windows Server 2008
#include <ws2tcpip.h>
#endif

#include <stdio.h>
#include <ziti/ziti_log.h>
#include <memory.h>
#include "ziti/ziti_tunnel_cbs.h"

IMPL_MODEL(tunneler_app_data, TUNNELER_APP_DATA_MODEL)

static void ziti_conn_close_cb(ziti_connection zc);

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
        int accepted = ziti_tunneler_write(io->tnlr_io, data, len);
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

/** called by tunneler SDK after a client connection is closed */
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

static char *string_replace(char *source, size_t sourceSize, const char *substring, const char *with) {
    char *substring_source = strstr(source, substring);
    if (substring_source == NULL) {
        return NULL;
    }

    if (sourceSize < strlen(source) + (strlen(with) - strlen(substring)) + 1) {
        ZITI_LOG(DEBUG, "replacing %s with %s in %s - not enough space", substring, with, source);
        return NULL;
    }

    memmove(
            substring_source + strlen(with),
            substring_source + strlen(substring),
            strlen(substring_source) - strlen(substring) + 1
    );

    memcpy(substring_source, with, strlen(with));
    return substring_source + strlen(with);
}

/** render app_data as string (json) into supplied buffer. returns json string length. */
static size_t get_app_data_json(char *buf, size_t bufsz, tunneler_io_context io, ziti_context ziti_ctx, const char *source_ip) {
    tunneler_app_data app_data_model;
    memset(&app_data_model, 0, sizeof(app_data_model));
    model_map_clear(&app_data_model.data, NULL);

    const char *intercepted = get_intercepted_address(io);
    if (intercepted != NULL) {
        char proto[8];
        char ip[64];

        const char *proto_sep = strchr(intercepted, ':');
        if (proto_sep != NULL) {
            snprintf(proto, sizeof(proto), "%.*s", (int) (proto_sep - intercepted), intercepted);
            model_map_set(&app_data_model.data, "intercepted_protocol", proto);
        }

        const char *ip_start = proto_sep + 1;
        const char *ip_sep = strrchr(intercepted, ':');
        if (ip_sep != NULL) {
            snprintf(ip, sizeof(ip), "%.*s", (int) (ip_sep - ip_start), ip_start);
            model_map_set(&app_data_model.data, "intercepted_ip", ip);
        }

        const char *port = ip_sep + 1;
        model_map_set(&app_data_model.data, "intercepted_port", (char *) port);
    }

    char resolved_source_ip[64];
    if (source_ip != NULL) {
        const ziti_identity *zid = ziti_get_identity(ziti_ctx);
        strncpy(resolved_source_ip, source_ip, sizeof(resolved_source_ip));
        string_replace(resolved_source_ip, sizeof(resolved_source_ip), "$tunneler_id.name", zid->name);
        char *tag_ref_start = strstr(resolved_source_ip, "$tunneler_id.tag[");
        if (tag_ref_start != NULL) {
            char tag_name[32];
            if (sscanf(tag_ref_start, "$tunneler_id.tag[%32[^]]", tag_name) > 0) {
                // currently won't work due to https://github.com/openziti/ziti-sdk-c/issues/138
                const char *tag_value = model_map_get(&zid->tags, tag_name);
                if (tag_value != NULL) {
                    char tag_ref[32];
                    snprintf(tag_ref, sizeof(tag_ref), "$tunneler_id.tag[%s]", tag_name);
                    string_replace(resolved_source_ip, sizeof(resolved_source_ip), tag_ref, tag_value);
                } else {
                    ZITI_LOG(WARN, "cannot set source_ip='%s': identity %s has no tag named '%s'",
                             source_ip, zid->name, tag_name);
                }
            }
        }
        string_replace(resolved_source_ip, sizeof(resolved_source_ip), "$intercepted_port", model_map_get(&app_data_model.data, "intercepted_port"));
        model_map_set(&app_data_model.data, "source_ip", resolved_source_ip);
    }

    size_t json_len;
    if (json_from_tunneler_app_data(&app_data_model, buf, bufsz, &json_len) != 0) {
        ZITI_LOG(ERROR, "encoded app data length %ld bytes exceeds %ld byte limit ", json_len, sizeof(json));
        json_len = 0;
    }

    //free_tunneler_app_data(&app_data_model); // todo leak?
    return json_len;
}

static void dial_opts_from_client_cfg_v1(ziti_dial_opts *opts, const ziti_client_cfg_v1 *config) {
}

/** initialize dial options from a ziti_intercept_cfg_v1 */
static void dial_opts_from_intercept_cfg_v1(ziti_dial_opts *opts, ziti_intercept_cfg_v1 *config) {
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
void * ziti_sdk_c_dial(const intercept_ctx_t *intercept_ctx, struct io_ctx_s *io) {
    if (intercept_ctx == NULL) {
        ZITI_LOG(WARN, "null intercept_ctx");
        return NULL;
    }
    ZITI_LOG(VERBOSE, "ziti_dial(name=%s)", intercept_ctx->service_name);

    ziti_io_context *ziti_io_ctx = malloc(sizeof(struct ziti_io_ctx_s));
    if (ziti_io_ctx == NULL) {
        ZITI_LOG(ERROR, "failed to allocate io context");
        return NULL;
    }
    io->ziti_io = ziti_io_ctx;

    ziti_context ziti_ctx = (ziti_context)intercept_ctx->ziti_ctx;
    if (ziti_conn_init(ziti_ctx, &ziti_io_ctx->ziti_conn, io) != ZITI_OK) {
        ZITI_LOG(ERROR, "ziti_conn_init failed");
        free(ziti_io_ctx);
        return NULL;
    }

    ziti_dial_opts dial_opts;
    memset(&dial_opts, 0, sizeof(dial_opts));
    char app_data_json[256];
    const char *source_ip = NULL;

    switch (intercept_ctx->cfg_type) {
        case CLIENT_CFG_V1:
            dial_opts_from_client_cfg_v1(&dial_opts, (ziti_client_cfg_v1 *)intercept_ctx->cfg);
            break;
        case INTERCEPT_CFG_V1:
            dial_opts_from_intercept_cfg_v1(&dial_opts, (ziti_intercept_cfg_v1 *)intercept_ctx->cfg);
            source_ip = ((ziti_intercept_cfg_v1 *)intercept_ctx->cfg)->source_ip;
            break;
        default:
            break;
    }

    dial_opts.app_data_sz = get_app_data_json(app_data_json, sizeof(app_data_json), io->tnlr_io, ziti_ctx, source_ip) + 1;
    dial_opts.app_data = app_data_json;

    ZITI_LOG(DEBUG, "service[%s] app_data_json='%s'", intercept_ctx->service_name, app_data_json);
    if (ziti_dial_with_options(ziti_io_ctx->ziti_conn, intercept_ctx->service_name, &dial_opts, on_ziti_connect, on_ziti_data) != ZITI_OK) {
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
    free(ctx);
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
    ZITI_LOG(VERBOSE, "nulled data for ziti_conn[%p]");
}