#if _WIN32
// _WIN32_WINNT needs to be declared and needs to be > 0x600 in order for 
// some constants used below to be declared
#define _WIN32_WINNT  _WIN32_WINNT_WIN6
 // Windows Server 2008
#include <ws2tcpip.h>
#endif

/*
 * - crash when removing service that is being hosted?
 * - crash when dialing underlay for hosted service and server is not there?
 * - dns udp hosted?
 */
#include <stdio.h>
#include <ziti/ziti_log.h>
#include <memory.h>
#include "ziti/ziti_tunnel_cbs.h"

IMPL_MODEL(tunneler_app_data, TUNNELER_APP_DATA_MODEL)

void on_ziti_connect(ziti_connection conn, int status) {
    ZITI_LOG(VERBOSE, "on_ziti_connect status: %d", status);
    struct io_ctx_s *io = ziti_conn_data(conn);
    if (io == NULL) {
        ZITI_LOG(WARN, "null io");
        return;
    }
    if (status == ZITI_OK) {
        ziti_tunneler_dial_completed(io, status == ZITI_OK);
    } else {
        ZITI_LOG(ERROR, "ziti dial failed: %s", ziti_errorstr(status));
        free(io->ziti_io);
        io->ziti_io = NULL;
    }
}

/** called by ziti SDK when ziti service has data for the client */
ssize_t on_ziti_data(ziti_connection conn, uint8_t *data, ssize_t len) {
    struct io_ctx_s *io = ziti_conn_data(conn);
    ZITI_LOG(TRACE, "got %zd bytes from ziti", len);
    if (io == NULL) {
        ZITI_LOG(WARN, "null io");
        return UV_ECONNABORTED;
    }
    ziti_io_context *ziti_io_ctx = io->ziti_io;
    if (io->ziti_io == NULL || io->tnlr_io == NULL) {
        ZITI_LOG(DEBUG, "null io_context - connection may have been closed already");
        ziti_conn_set_data(conn, NULL);
        ziti_close(&conn);
        if (io->ziti_io) free(io->ziti_io);
        io->ziti_io = NULL;
        return UV_ECONNABORTED;
    }
    if (len > 0) {
        int accepted = ziti_tunneler_write(&io->tnlr_io, data, len);
        if (accepted < 0) {
            ziti_sdk_c_close(io->ziti_io);
        }
        return accepted;
    } else if (len == ZITI_EOF) {
        ZITI_LOG(DEBUG, "ziti connection sent EOF (ziti_eof=%d, tnlr_eof=%d)", ziti_io_ctx->ziti_eof, ziti_io_ctx->tnlr_eof);
        ziti_io_ctx->ziti_eof = true;
        if (ziti_io_ctx->tnlr_eof) /* both sides are closed now */ {
            ziti_tunneler_close(&io->tnlr_io);
            ziti_conn_set_data(conn, NULL);
            free(ziti_io_ctx);
            free(io);
        } else {
            ziti_tunneler_close_write(&io->tnlr_io);
        }
    } else if (len < 0) {
        int log_level = ERROR;
        if (len == ZITI_CONN_CLOSED) log_level = DEBUG;
        ZITI_LOG(log_level, "ziti connection is closed due to [%zd](%s)", len, ziti_errorstr(len));
        ziti_tunneler_close(&io->tnlr_io);
        ziti_conn_set_data(conn, NULL);
        free(ziti_io_ctx);
        free(io);
    }
    return len;
}

/** called by tunneler SDK after a client connection is closed */
int ziti_sdk_c_close(void *io_ctx) {
    ziti_io_context *ziti_io_ctx = io_ctx;
    if (ziti_io_ctx->ziti_conn != NULL) {
        ZITI_LOG(DEBUG, "closing ziti_conn tnlr_eof=%d, ziti_eof=%d", ziti_io_ctx->tnlr_eof, ziti_io_ctx->ziti_eof);
        ziti_io_ctx->tnlr_eof = true;
        if (ziti_io_ctx->ziti_eof) { // both sides are now closed
            ZITI_LOG(DEBUG, "closing ziti_conn tnlr_eof=%d, ziti_eof=%d", ziti_io_ctx->tnlr_eof, ziti_io_ctx->ziti_eof);
            ziti_close(&ziti_io_ctx->ziti_conn);
            free(ziti_io_ctx);
            return 1;
        } else {
            ZITI_LOG(DEBUG, "closing ziti_conn tnlr_eof=%d, ziti_eof=%d", ziti_io_ctx->tnlr_eof, ziti_io_ctx->ziti_eof);
            ziti_close_write(ziti_io_ctx->ziti_conn);
            return 0;
        }
    }
    return 1;
}

/** render app_data as string (json) into supplied buffer. returns json string length. */
static size_t get_app_data_json(char *buf, size_t bufsz, tunneler_io_context io, const char *source_ip) {
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

    if (source_ip != NULL) {
        model_map_set(&app_data_model.data, "source_ip", (char *) source_ip);
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

    const ziti_identity *zid = ziti_get_identity((ziti_context)intercept_ctx->ziti_ctx);

    switch (intercept_ctx->cfg_type) {
        case CLIENT_CFG_V1:
            dial_opts_from_client_cfg_v1(&dial_opts, (ziti_client_cfg_v1 *)intercept_ctx->cfg);
            dial_opts.app_data_sz = get_app_data_json(app_data_json, sizeof(app_data_json), tnlr_io_ctx, NULL) + 1;
            dial_opts.app_data = app_data_json;
            break;
        case INTERCEPT_CFG_V1:
            dial_opts_from_intercept_cfg_v1(&dial_opts, (ziti_intercept_cfg_v1 *)intercept_ctx->cfg);
            dial_opts.app_data_sz = get_app_data_json(app_data_json, sizeof(app_data_json), tnlr_io_ctx, ((ziti_intercept_cfg_v1 *)intercept_ctx->cfg)->source_ip) + 1;
            dial_opts.app_data = app_data_json;
            break;
        default:
            break;
    }

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
    ziti_tunneler_ack(ctx);
}

/** called from tunneler SDK when intercepted client sends data */
ssize_t ziti_sdk_c_write(const void *ziti_io_ctx, void *write_ctx, const void *data, size_t len) {
    struct ziti_io_ctx_s *_ziti_io_ctx = (struct ziti_io_ctx_s *)ziti_io_ctx;
    return ziti_write(_ziti_io_ctx->ziti_conn, (void *)data, len, on_ziti_write, write_ctx);
}

/********** hosting **********/

/** called by ziti SDK when a ziti client write (to a hosted tcp server) is completed */
static void on_hosted_tcp_client_write(uv_write_t *req, int status) {
    free(req->data);
    free(req);
}

/** */
static void on_hosted_udp_client_write(uv_udp_send_t* req, int status) {
    free(req->data);
    free(req);
}

#define safe_free(p) if ((p) != NULL) free((p))

static void free_hosted_service_ctx(struct hosted_service_ctx_s *hosted_ctx) {
    if (hosted_ctx == NULL) {
        return;
    }
    safe_free(hosted_ctx->service_name);
    switch (hosted_ctx->cfg_type) {
        case HOST_CFG_V1:
            free_ziti_host_cfg_v1((ziti_host_cfg_v1 *)hosted_ctx->cfg);
            break;
        case SERVER_CFG_V1:
            free_ziti_server_cfg_v1((ziti_server_cfg_v1 *)hosted_ctx->cfg);
            break;
        default:
            ZITI_LOG(DEBUG, "unexpected cfg_type %d", hosted_ctx->cfg_type);
            break;
    }
}

static void free_hosted_io_ctx(struct hosted_io_ctx_s *io_ctx) {
    if (io_ctx == NULL) {
        return;
    }
    free(io_ctx);
}

static void hosted_server_close_cb(uv_handle_t *handle) {
    free_hosted_io_ctx(handle->data);
}

static void tcp_shutdown_cb(uv_shutdown_t *req, int res) {
    free(req);
}

/* called by ziti sdk when a client of a hosted service sends data */
static ssize_t on_hosted_client_data(ziti_connection clt, uint8_t *data, ssize_t len) {
    struct hosted_io_ctx_s *io_ctx = ziti_conn_data(clt);
    if (len > 0) {
        char *copy = malloc(len);
        memcpy(copy, data, len);
        uv_buf_t buf = uv_buf_init(copy, len);
        switch (io_ctx->service->proto_id) {
            case IPPROTO_TCP: {
                uv_write_t *req = malloc(sizeof(uv_write_t));
                req->data = copy;
                uv_write(req, (uv_stream_t *) &io_ctx->server.tcp, &buf, 1, on_hosted_tcp_client_write);
                }
                break;
            case IPPROTO_UDP: {
                uv_udp_send_t *req = malloc(sizeof(uv_udp_send_t));
                req->data = copy;
                uv_udp_send(req, &io_ctx->server.udp, &buf, 1, NULL, on_hosted_udp_client_write);
                }
                break;
            default:
                ZITI_LOG(ERROR, "invalid protocol %s in server config for service %s", io_ctx->service->proto, io_ctx->service->service_name);
                break;
        }
    }
    else if (len == ZITI_EOF) {
        ZITI_LOG(INFO, "client sent EOF, ziti_eof=%d, tcp_eof=%d", io_ctx->ziti_eof, io_ctx->tcp_eof);
        io_ctx->ziti_eof = true;
        switch (io_ctx->service->proto_id) {
            case IPPROTO_TCP:
                if (io_ctx->tcp_eof) {
                    ziti_close(&clt);
                    uv_close((uv_handle_t *)&io_ctx->server.tcp, hosted_server_close_cb);
                } else {
                    uv_shutdown_t *shut = calloc(1, sizeof(uv_shutdown_t));
                    uv_shutdown(shut, (uv_stream_t *) &io_ctx->server.tcp, tcp_shutdown_cb);
                }
                break;
            case IPPROTO_UDP:
                uv_close((uv_handle_t *)&io_ctx->server.udp, NULL);
                break;
        }
    }
    else {
        ZITI_LOG(ERROR, "error: %zd(%s)", len, ziti_errorstr(len));
    }
    return len;
}

#define ZITI_MTU (15 * 1024)
static void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    *buf = uv_buf_init((char*) malloc(ZITI_MTU), ZITI_MTU);
}

/** called by ziti SDK when data transfer initiated by ziti_write completes */
static void on_hosted_ziti_write(ziti_connection ziti_conn, ssize_t len, void *ctx) {
    free(ctx);
}

/** called by libuv when a hosted TCP server sends data to a client */
static void on_hosted_tcp_server_data(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    struct hosted_io_ctx_s *io_ctx = stream->data;
    if (io_ctx == NULL) {
        ZITI_LOG(ERROR, "null io_ctx");
        if (nread > 0) {
            free(buf->base);
        }
        return;
    }

    if (io_ctx->client == NULL) {
        ZITI_LOG(ERROR, "null client. did server side close?");
        if (nread > 0) {
            free(buf->base);
        }
        return;
    }

    if (nread > 0) {
        ziti_write(io_ctx->client, buf->base, nread, on_hosted_ziti_write, buf->base);
    } else {
        if (nread == UV_EOF) {
            ZITI_LOG(INFO, "server sent FIN ziti_eof=%d, tcp_eof=%d", io_ctx->ziti_eof, io_ctx->tcp_eof);
            if (io_ctx->ziti_eof) {
                ziti_close(&io_ctx->client);
                uv_close((uv_handle_t *) &io_ctx->server.tcp, hosted_server_close_cb);
            } else {
                ziti_close_write(io_ctx->client);
            }
        } else {
            ZITI_LOG(WARN, "error reading from server");
            ziti_close(&io_ctx->client);
        }
    }
}

/** called by libuv when a hosted UDP server sends data to a client */
static void on_hosted_udp_server_data(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags) {
    struct hosted_io_ctx_s *io_ctx = handle->data;
    if (nread > 0) {
        ziti_write(io_ctx->client, buf->base, nread, on_hosted_ziti_write, buf->base);
    } else if (addr == NULL && nread != 0) {
        if (buf->base != NULL) {
            free(buf->base);
        }
        ZITI_LOG(ERROR, "error receiving data from hosted service %s", io_ctx->service->service_name);
        ziti_close(&io_ctx->client);
    }
}

/** called by ziti sdk when a client connection is established (or fails) */
static void on_hosted_client_connect_complete(ziti_connection clt, int err) {
    struct hosted_io_ctx_s *io_ctx = ziti_conn_data(clt);
    if (err == ZITI_OK) {
        ZITI_LOG(INFO, "client connected to hosted service %s", io_ctx->service->service_name);
        switch (io_ctx->service->proto_id) {
            case IPPROTO_TCP:
                uv_read_start((uv_stream_t *) &io_ctx->server.tcp, alloc_buffer, on_hosted_tcp_server_data);
                break;
            case IPPROTO_UDP:
                uv_udp_recv_start(&io_ctx->server.udp, alloc_buffer, on_hosted_udp_server_data);
                break;
        }
    } else {
        ZITI_LOG(ERROR, "client failed to connect to hosted service %s: %s", io_ctx->service->service_name,
                 ziti_errorstr(err));
    }
}

/**
 * called by libuv when a connection is established (or failed) with a TCP server
 *
 *  c is the uv_tcp_connect_t that was initialized in on_hosted_client_connect_complete
 *  c->handle is the uv_tcp_t (server stream) that was initialized in on_hosted_client_connect
 */
static void on_hosted_tcp_server_connect_complete(uv_connect_t *c, int status) {
    if (c == NULL || c->handle == NULL || c->handle->data == NULL) {
        ZITI_LOG(ERROR, "null handle or io_ctx");
    }
    struct hosted_io_ctx_s *io_ctx = c->handle->data;
    if (status < 0) {
        ZITI_LOG(ERROR, "connect hosted service %s to %s:%s:%d failed: %s", io_ctx->service->service_name,
                 io_ctx->service->proto, io_ctx->service->hostname, io_ctx->service->port, uv_strerror(status));
        ziti_close(&io_ctx->client);
        free(c);
        return;
    }
    ZITI_LOG(INFO, "connected to server for client %p: %p", c->handle->data, c);
    ziti_accept(io_ctx->client, on_hosted_client_connect_complete, on_hosted_client_data);
    free(c);
}

#if 0
bool tag_map_string_value(model_map *map, const char *key, char **value) {
    tag *t = model_map_get(map, key);
    if (t == NULL) {
        ZITI_LOG(DEBUG, "key %s does not exist in map %p", key, map);
        return false;
    }

    if (t->type != tag_string) {
        ZITI_LOG(DEBUG, "value of key %s in map %p has non-string type %d", key, map, t->type);
        return false;
    }

    *value = t->string_value;
    return true;
}

bool tag_map_num_value(model_map *map, const char *key, int *value) {
    tag *t = model_map_get(map, key);
    if (t == NULL) {
        ZITI_LOG(DEBUG, "key %s does not exist in map %p", key, map);
        return false;
    }

    if (t->type != tag_number) {
        ZITI_LOG(DEBUG, "value of key %s in map %p has non-number type %d", key, map, t->type);
        return false;
    }

    *value = t->num_value;
    return true;
}

typedef struct app_data_s {
    const char *intercepted_protocol;
    const char *intercepted_ip;
    int intercepted_port;
    const char *source_ip;
} app_data_t;

static void extract_app_data_values(const char *app_data_json, app_data_t *app_data) {
    app_data->intercepted_protocol = NULL;
    app_data->intercepted_ip = NULL;
    app_data->intercepted_port = -1;
    app_data->source_ip = NULL;

    if (app_data_json != NULL) {
        tunneler_app_data ad;
        parse_tunneler_app_data(&ad, app_data_json, strlen(app_data_json));
        tag_map_string_value(&ad.data, "intercepted_protocol", (char **)&app_data->intercepted_protocol);
        tag_map_string_value(&ad.data, "intercepted_ip", (char **)&app_data->intercepted_ip);
        tag_map_num_value(&ad.data, "intercepted_port", &app_data->intercepted_port);
        tag_map_string_value(&ad.data, "source_ip", (char **)&app_data->source_ip);
    }
}
#endif

struct addrinfo_params_s {
    const char *    address;
    const char *    port;
    struct addrinfo hints;
    char            err[64];
};

static int get_protocol_id(const char *protocol) {
    if (strcasecmp(protocol, "tcp") == 0) {
        return IPPROTO_TCP;
    } else if (strcasecmp(protocol, "udp") == 0) {
        return IPPROTO_UDP;
    }
    return -1;
#if 0
    } else {
    }
#endif
}

static bool addrinfo_from_host_cfg_v1(struct addrinfo_params_s *dial_params, const ziti_host_cfg_v1 *config, model_map *app_data) {
    const char *dial_protocol_str = NULL;

    memset(dial_params, 0, sizeof(struct addrinfo_params_s));

    if (config->dial_intercepted_protocol) {
        dial_protocol_str = model_map_get(app_data, "intercepted_protocol");
        if (dial_protocol_str == NULL) {
            snprintf(dial_params->err, sizeof(dial_params->err),
                     "service config specifies 'dialInterceptedProtocol', but client didn't send intercepted protocol");
            return false;
        }
    } else {
        dial_protocol_str = config->protocol;
    }

    dial_params->hints.ai_protocol = get_protocol_id(dial_protocol_str);
    if (dial_params->hints.ai_protocol < 0) {
        snprintf(dial_params->err, sizeof(dial_params->err), "unsupported dial protocol '%s'", dial_protocol_str);
        return false;
    }

    if (config->dial_intercepted_address) {
        dial_params->address = model_map_get(app_data, "intercepted_ip");
        if (dial_params->address == NULL) {
            snprintf(dial_params->err, sizeof(dial_params->err),
                     "service config specifies 'dialInterceptedAddress' but client didn't send intercepted ip");
            return false;
        }
    } else {
        dial_params->address = config->address;
    }

    char dial_port_str_from_config[12];
    if (config->dial_intercepted_port) {
        dial_params->port = model_map_get(app_data, "intercepted_port");
        if (dial_params->port == NULL) {
            snprintf(dial_params->err, sizeof(dial_params->err),
                     "service config specifies 'dialInterceptedPort' but client didn't send intercepted port");
            return false;
        } else {
            strtol(dial_params->port, NULL, 10);
            if (errno != 0) {
                snprintf(dial_params->err, sizeof(dial_params->err),
                         "client sent invalid intercept port '%s'", dial_params->port);
                return false;
            }
        }
    } else {
        snprintf(dial_port_str_from_config, sizeof(dial_port_str_from_config), "%d", config->port);
        dial_params->port = dial_port_str_from_config;
    }

    dial_params->hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV;
    switch (dial_params->hints.ai_protocol) {
        case IPPROTO_TCP:
            dial_params->hints.ai_socktype = SOCK_STREAM;
            break;
        case IPPROTO_UDP:
            dial_params->hints.ai_socktype = SOCK_DGRAM;
            break;
        default:
            /* should not happen, since protocol is verified earlier */
            snprintf(dial_params->err, sizeof(dial_params->err), "unexpected protocol id %d", dial_params->hints.ai_protocol);
            return false;
    }
}

static bool addrinfo_from_server_cfg_v1(struct addrinfo_params_s *dial, const ziti_server_cfg_v1 *config, model_map *app_data) {
    return false;
}

/** called by ziti sdk when a ziti endpoint (client) initiates connection to a hosted service */
static void on_hosted_client_connect(ziti_connection serv, ziti_connection clt, int status) {
    struct hosted_service_ctx_s *service_ctx = ziti_conn_data(serv);

    if (service_ctx == NULL) {
        ZITI_LOG(ERROR, "null service_ctx");
        ziti_close(&clt);
        return;
    }

    if (status != ZITI_OK) {
        ZITI_LOG(ERROR, "incoming connection to service[%s] failed: %s", service_ctx->service_name, ziti_errorstr(status));
        ziti_close(&clt);
        return;
    }

    const char *client_identity = ziti_conn_source_identity(clt);
    if (client_identity == NULL) client_identity = "<unidentified>";

    ZITI_LOG(INFO, "hosted_service[%s], client[%s]: incoming connection", service_ctx->service_name, client_identity);

    char *app_data_json = ziti_conn_data(clt);
    tunneler_app_data app_data_model;
    if (app_data_json != NULL) {
        ZITI_LOG(DEBUG, "hosted_service[%s], client[%s]: received app_data_json='%s'", service_ctx->service_name,
                 client_identity, app_data_json);
        if (parse_tunneler_app_data(&app_data_model, app_data_json, strlen(app_data_json)) != 0) {
            ZITI_LOG(ERROR, "hosted_service[%s], client[%s]: failed to parse app_data_json '%s'",
                     service_ctx->service_name,
                     client_identity, app_data_json);
            free_tunneler_app_data(&app_data_model);
            ziti_close(&clt);
        }
    }

    struct addrinfo_params_s dial_ai_params;
    int s = false;

    switch (service_ctx->cfg_type) {
        case HOST_CFG_V1:
            s = addrinfo_from_host_cfg_v1(&dial_ai_params, service_ctx->cfg, &app_data_model.data);
            break;
        case SERVER_CFG_V1:
            s = addrinfo_from_server_cfg_v1(&dial_ai_params, service_ctx->cfg, &app_data_model.data);
            break;
        default:
            ZITI_LOG(ERROR, "hosted_service[%s], client[%s]: unexpected cfg_type %d",
                     service_ctx->service_name, client_identity, service_ctx->cfg_type);
            free_tunneler_app_data(&app_data_model);
            ziti_close(&clt);
            break;
    }

    if (!s) {
        ZITI_LOG(ERROR, "hosted_service[%s], client[%s]: failed to create dial addrinfo params: %s",
                 service_ctx->service_name, client_identity, dial_ai_params.err);
        free_tunneler_app_data(&app_data_model);
        ziti_close(&clt);
    }

    struct addrinfo *dial_ai;
    if ((s = getaddrinfo(dial_ai_params.address, dial_ai_params.port, &dial_ai_params.hints, &dial_ai)) != 0) {
        ZITI_LOG(ERROR, "hosted_service[%s], client[%s]: getaddrinfo(%s,%s) failed: %s",
                 service_ctx->service_name, client_identity, dial_ai_params.address, dial_ai_params.port, gai_strerror(s));
        free_tunneler_app_data(&app_data_model);
        ziti_close(&clt);
        return;
    }
    if (dial_ai->ai_next != NULL) {
        ZITI_LOG(DEBUG, "hosted_service[%s], client[%s]: getaddrinfo(%s,%s) returned multiple results; using first",
                 service_ctx->service_name, client_identity, dial_ai_params.address, dial_ai_params.port);
    }

    const char *iproto = model_map_get(&app_data_model.data, "intercepted_protocol");
    const char *iip = model_map_get(&app_data_model.data, "intercepted_ip");
    const char *iport = model_map_get(&app_data_model.data, "intercepted_port");
    if (iproto != NULL && iip != NULL && iport != NULL) {
        ZITI_LOG(INFO, "hosted_service[%s], client[%s] intercepted_addr[%s:%s:%s]: incoming connection",
                 service_ctx->service_name, client_identity, iproto, iip, iport);
    } else {
        ZITI_LOG(INFO, "hosted_service[%s], client[%s] incoming connection",
                 service_ctx->service_name, client_identity);
    }

    struct addrinfo source_hints;
    const char *source_ip = model_map_get(&app_data_model.data, "source_ip");
    if (source_ip != NULL) {
        source_hints.ai_flags = AI_ADDRCONFIG;
        source_hints.ai_flags |= AI_NUMERICHOST;
        source_hints.ai_protocol = dial_ai_params.hints.ai_protocol;
        source_hints.ai_socktype = dial_ai_params.hints.ai_socktype;
        if ((s = getaddrinfo(source_ip, NULL, &source_hints, &source_ai)) != 0) {
            ZITI_LOG(ERROR, "hosted_service[%s], client[%s]: getaddrinfo(%s,NULL) failed: %s",
                     service_ctx->service_name, client_identity, source_ip, gai_strerror(s));
            free_tunneler_app_data(&app_data_model);
            ziti_close(&clt);
            freeaddrinfo(dial_ai);
        }
        if (source_ai->ai_next != NULL) {
            ZITI_LOG(DEBUG, "hosted_service[%s], client[%s]: getaddrinfo(%s,NULL) returned multiple results; using first",
                     service_ctx->service_name, client_identity, source_ip);
        }
    }

    struct hosted_io_ctx_s *io_ctx = calloc(1, sizeof(struct hosted_io_ctx_s));
    io_ctx->service = service_ctx;
    io_ctx->client = clt;

    int uv_err;
    switch (dial_ai->ai_protocol) {
        case IPPROTO_TCP:
            uv_tcp_init(service_ctx->loop, &io_ctx->server.tcp);
            io_ctx->server.tcp.data = io_ctx;
            ziti_conn_set_data(clt, io_ctx);
            if (source_ai != NULL) {
                uv_err = uv_tcp_bind(&io_ctx->server.tcp, source_ai->ai_addr, 0);
                if (uv_err != 0) {
                    ZITI_LOG(ERROR, "hosted_service[%s], client[%s]: uv_tcp_bind failed: %s",
                             service_ctx->service_name, client_identity, uv_err_name(uv_err));
                    err = true;
                    goto done;
                }
            }
            {
                uv_connect_t *c = malloc(sizeof(uv_connect_t));
                uv_err = uv_tcp_connect(c, &io_ctx->server.tcp, dial_ai->ai_addr, on_hosted_tcp_server_connect_complete);
                if (uv_err != 0) {
                    ZITI_LOG(ERROR, "hosted_service[%s], client[%s]: tv_tcp_connect failed: %s",
                             service_ctx->service_name, client_identity, uv_err_name(uv_err));
                }
            }
            break;
        case IPPROTO_UDP:
            uv_udp_init(service_ctx->loop, &io_ctx->server.udp);
            io_ctx->server.udp.data = io_ctx;
            ziti_conn_set_data(clt, io_ctx);
            if (source_ai != NULL) {
                uv_err = uv_udp_bind(&io_ctx->server.udp, source_ai->ai_addr, 0);
                if (uv_err != 0) {
                    ZITI_LOG(ERROR, "hosted_service[%s] client[%s]: uv_udp_bind failed: %s",
                             service_ctx->service_name, client_identity, uv_err_name(uv_err));
                    err = true;
                    goto done;
                }
            }
            uv_err = uv_udp_connect(&io_ctx->server.udp, dial_ai->ai_addr);
            if (uv_err != 0) {
                ZITI_LOG(ERROR, "hosted_service[%s], client[%s]: uv_udp_connect failed: %s",
                         service_ctx->service_name, client_identity, uv_err_name(uv_err));
                err = true;
                goto done;
            }
            uv_err = uv_udp_recv_start(&io_ctx->server.udp, alloc_buffer, on_hosted_udp_server_data);
            if (uv_err != 0) {
                ZITI_LOG(ERROR, "hosted_service[%s] client[%s]: uv_udp_recv_start failed: %s",
                         service_ctx->service_name, client_identity, uv_err_name(uv_err));
                err = true;
                goto done;
            }
            if (ziti_accept(clt, on_hosted_client_connect_complete, on_hosted_client_data) != ZITI_OK) {
                ZITI_LOG(ERROR, "ziti_accept failed");
                err = true;
                goto done;
            }
            break;
    }

    free_tunneler_app_data(&app_data_model);
    ziti_close(&clt);
    freeaddrinfo(dial_ai);
    freeaddrinfo(source_ai);
}

/** called by ziti SDK when a hosted service listener is ready */
static void hosted_listen_cb(ziti_connection serv, int status) {
    struct hosted_service_ctx_s *host_ctx = ziti_conn_data(serv);
    if (host_ctx == NULL) {
        ZITI_LOG(DEBUG, "null host_ctx");
        return;
    }

    if (status != ZITI_OK) {
        ZITI_LOG(ERROR, "unable to host service %s: %s", host_ctx->service_name, ziti_errorstr(status));
        free_hosted_service_ctx(host_ctx);
    }
}

/** called by the tunneler sdk when a hosted service becomes available */
void ziti_sdk_c_host_v1(void *ziti_ctx, uv_loop_t *loop, const char *service_name, const char *proto, const char *hostname, int port) {
    if (service_name == NULL) {
        ZITI_LOG(ERROR, "null service_name");
        return;
    }
    if (proto == NULL || strlen(proto) == 0) {
        ZITI_LOG(ERROR, "cannot host service %s: null or empty protocol", service_name);
        return;
    }
    if (hostname == NULL || strlen(hostname) == 0) {
        ZITI_LOG(ERROR, "cannot host service %s: null or empty hostname", service_name);
        return;
    }
    if (port <= 0) {
        ZITI_LOG(ERROR, "cannot host service %s: invalid port %d", service_name, port);
        return;
    }
    int proto_id;
    if (strcasecmp(proto, "tcp") == 0) {
        proto_id = IPPROTO_TCP;
    } else if (strcasecmp(proto, "udp") == 0) {
        proto_id = IPPROTO_UDP;
    } else {
        ZITI_LOG(ERROR, "cannot host service %s: unsupported protocol '%s'", service_name, proto);
        return;
    }

    struct hosted_service_ctx_s *service_ctx = calloc(1, sizeof(struct hosted_service_ctx_s));
    service_ctx->service_name = strdup(service_name);
    service_ctx->proto = strdup(proto);
    service_ctx->proto_id = proto_id;
    service_ctx->hostname = strdup(hostname);
    service_ctx->port = port;
    service_ctx->ziti_ctx = ziti_ctx;
    service_ctx->loop = loop;

    ziti_connection serv;
    ziti_conn_init(ziti_ctx, &serv, service_ctx);
    ziti_listen(serv, service_name, hosted_listen_cb, on_hosted_client_connect);
}

static void listen_opts_from_server_cfg_v1() {

}

static void listen_opts_from_host_cfg_v1(ziti_listen_opts *opts, ziti_host_cfg_v1 *config) {
    opts->identity = "";
    opts->connect_timeout_seconds = 0;
    opts->bind_using_edge_identity = false;
    opts->terminator_precedence = PRECEDENCE_DEFAULT;
    opts->terminator_cost = 0;
}

void ziti_sdk_c_host(void *ziti_ctx, uv_loop_t *loop, const char *service_name, cfg_type_e cfg_type, const void *cfg) {
    if (service_name == NULL) {
        ZITI_LOG(ERROR, "null service_name");
        return;
    }

    ziti_listen_opts listen_opts;
    ziti_listen_opts *listen_opts_p = NULL;
    switch (cfg_type) {
        case HOST_CFG_V1:
            listen_opts_from_host_cfg_v1(&listen_opts, cfg);
            listen_opts_p = &listen_opts;
            break;
        case SERVER_CFG_V1:
            break;
        default:
            ZITI_LOG(WARN, "unexpected cfg_type %d", cfg_type);
            break;
    }

    struct hosted_service_ctx_s *host_ctx = calloc(1, sizeof(struct hosted_service_ctx_s));
    host_ctx->service_name = strdup(service_name);
    host_ctx->ziti_ctx = ziti_ctx;
    host_ctx->loop = loop;
    host_ctx->cfg_type = cfg_type;
    host_ctx->cfg = cfg;

    ziti_connection serv;
    ziti_conn_init(ziti_ctx, &serv, host_ctx);

    ziti_listen_with_options(serv, service_name, listen_opts_p, hosted_listen_cb, on_hosted_client_connect);
}

intercept_ctx_t *new_intercept_ctx(tunneler_context tnlr_ctx, const void *ziti_ctx, const char *service_name, cfg_type_e cfg_type, const void *cfg) {
    intercept_ctx_t *i_ctx = calloc(1, sizeof(intercept_ctx_t));
    int i;

    i_ctx->ziti_ctx = ziti_ctx;
    i_ctx->service_name = service_name;

    STAILQ_INIT(&i_ctx->protocols);
    STAILQ_INIT(&i_ctx->cidrs);
    STAILQ_INIT(&i_ctx->port_ranges);

    switch (cfg_type) {
        case CLIENT_CFG_V1:
            intercept_ctx_add_protocol(i_ctx, "udp");
            intercept_ctx_add_protocol(i_ctx, "tcp");
            intercept_ctx_add_address(tnlr_ctx, i_ctx, ((ziti_client_cfg_v1 *) cfg)->hostname);
            intercept_ctx_add_port_range(i_ctx, ((ziti_client_cfg_v1 *)cfg)->port, ((ziti_client_cfg_v1 *)cfg)->port);
            break;
        case INTERCEPT_CFG_V1:
            {
                const ziti_intercept_cfg_v1 *config = cfg;
                for (i = 0; config->protocols[i] != NULL; i++) {
                    intercept_ctx_add_protocol(i_ctx, ((ziti_intercept_cfg_v1 *)cfg)->protocols[i]);
                }
                for (i = 0; config->addresses[i] != NULL; i++) {
                    intercept_ctx_add_address(tnlr_ctx, i_ctx, config->addresses[i]);
                }
                for (i = 0; config->port_ranges[i] != NULL; i++) {
                    intercept_ctx_add_port_range(i_ctx, config->port_ranges[i]->low, config->port_ranges[i]->high);
                }
            }
            break;
        default:
            break;
    }

    i_ctx->cfg_type = cfg_type;
    i_ctx->cfg = cfg;

    return i_ctx;
}

typedef int (*cfg_parse_fn)(void *, const char *, size_t);
typedef void* (*cfg_alloc_fn)();
typedef void (*cfg_free_fn)(void *);

typedef struct cfgtype_desc_s {
    const char *name;
    cfg_alloc_fn alloc;
    cfg_free_fn free;
    cfg_parse_fn parse;
} cfgtype_desc_t;

#define CFGTYPE_DESC(name, type) { name, alloc_##type, free_##type, parse_##type }

static struct cfgtype_desc_s intercept_cfgtypes[] = {
        CFGTYPE_DESC("intercept.v1", ziti_intercept_cfg_v1),
        CFGTYPE_DESC("ziti-tunneler-client.v1", ziti_client_cfg_v1)
};

static struct cfgtype_desc_s host_cfgtypes[] = {
        CFGTYPE_DESC("host.v1", ziti_host_cfg_v1),
        CFGTYPE_DESC("ziti-tunneler-server.v1", ziti_server_cfg_v1)
};

/** set up intercept or host context according to service permissions and configuration */
void ziti_sdk_c_on_service(ziti_context ziti_ctx, ziti_service *service, int status, void *tnlr_ctx) {
    if (status == ZITI_OK) {
        int i, get_config_rc;
        cfgtype_desc_t *cfgtype;
        void *config;
        if (service->perm_flags & ZITI_CAN_DIAL) {
            bool intercepted = false;
            for (i = 0; i < sizeof(intercept_cfgtypes) / sizeof(cfgtype_desc_t); i++) {
                cfgtype = &intercept_cfgtypes[i];
                config = cfgtype->alloc();
                get_config_rc = ziti_service_get_config(service, cfgtype->name, config, cfgtype->parse);
                if (get_config_rc == 0) {
                    intercept_ctx_t *i_ctx = new_intercept_ctx(tnlr_ctx, ziti_ctx, service->name, INTERCEPT_CFG_V1, config);
                    ziti_tunneler_intercept(tnlr_ctx, i_ctx);
                    intercepted = true;
                    break;
                }
                cfgtype->free(config);
            }
            if (!intercepted) {
                ZITI_LOG(WARN, "service[%s] can be dialed, but lacks intercept configuration; not intercepting", service->name);
            }
        }
        if (service->perm_flags & ZITI_CAN_BIND) {
            bool hosted = false;
            for (i = 0; i < sizeof(host_cfgtypes) / sizeof(cfgtype_desc_t); i++) {
                cfgtype_desc_t *cfgtype = &host_cfgtypes[i];
                config = cfgtype->alloc();
                get_config_rc = ziti_service_get_config(service, cfgtype->name, config, cfgtype->parse);
                if (get_config_rc == 0) {
//                    ZITI_LOG(INFO, "service_available: %s => %s:%s:%d", service->name, config->protocol,
//                             config->hostname, config->port);
                    ziti_tunneler_host(tnlr_ctx, ziti_ctx, service->name, cfgtype->cfgtype, config);
                    hosted = true;
                    break;
                }
                cfgtype->free(config);
            }
            if (!hosted) {
                ZITI_LOG(INFO, "service[%s] can be bound, but lacks host configuration; not hosting", service->name);
            }
        }
    } else if (status == ZITI_SERVICE_UNAVAILABLE) {
        ZITI_LOG(INFO, "service unavailable: %s", service->name);
        ziti_tunneler_stop_intercepting(tnlr_ctx, ziti_ctx, service->name);
        // todo lookup intercept_ctx by name and free config
    }

}