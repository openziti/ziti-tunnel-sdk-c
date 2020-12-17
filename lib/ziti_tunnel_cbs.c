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
    if (io_ctx == NULL) {
        ZITI_LOG(DEBUG, "null io_ctx");
        return 1;
    }
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
    if (io_ctx == NULL) {
        ZITI_LOG(DEBUG, "null io_ctx");
        return 0;
    }
    if (len > 0) {
        char *copy = malloc(len);
        memcpy(copy, data, len);
        uv_buf_t buf = uv_buf_init(copy, len);
        switch (io_ctx->server_proto_id) {
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
                ZITI_LOG(ERROR, "invalid protocol %d in server config for service %s", io_ctx->server_proto_id, io_ctx->service->service_name);
                break;
        }
    }
    else if (len == ZITI_EOF) {
        ZITI_LOG(INFO, "hosted_service[%s] client[%s] sent EOF, ziti_eof=%d, tcp_eof=%d", io_ctx->service->service_name,
                 ziti_conn_source_identity(clt), io_ctx->ziti_eof, io_ctx->tcp_eof);
        io_ctx->ziti_eof = true;
        switch (io_ctx->server_proto_id) {
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
        int log_level = ERROR;
        if (len == ZITI_CONN_CLOSED) log_level = DEBUG;
        ZITI_LOG(log_level, "hosted_service[%s] client[%s] ziti conn err %zd(%s)", io_ctx->service->service_name,
                 ziti_conn_source_identity(clt), len, ziti_errorstr(len));
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
        if (buf->base) free(buf->base);
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
        if (nread == UV_ENOBUFS) {
            ZITI_LOG(WARN, "tcp server is throttled: could not allocate buffer for incoming data [%zd](%s)", nread, uv_strerror(nread));
        } else if (nread == UV_EOF) {
            ZITI_LOG(DEBUG, "server sent FIN ziti_eof=%d, tcp_eof=%d", io_ctx->ziti_eof, io_ctx->tcp_eof);
            if (io_ctx->ziti_eof) {
                ziti_close(&io_ctx->client);
                uv_close((uv_handle_t *) &io_ctx->server.tcp, hosted_server_close_cb);
            } else {
                ziti_close_write(io_ctx->client);
            }
        } else {
            ZITI_LOG(WARN, "error reading from server [%zd](%s)", nread, uv_strerror(nread));
            ziti_close(&io_ctx->client);
        }

        if (buf->base)
            free(buf->base);
    }
}

/** called by libuv when a hosted UDP server sends data to a client */
static void on_hosted_udp_server_data(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags) {
    struct hosted_io_ctx_s *io_ctx = handle->data;
    if (io_ctx == NULL) {
        ZITI_LOG(DEBUG, "null io_ctx");
        return;
    }
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
    if (io_ctx == NULL) {
        ZITI_LOG(DEBUG, "null io_ctx");
        return;
    }
    if (err == ZITI_OK) {
        ZITI_LOG(INFO, "hosted_service[%s] client[%s] connected", io_ctx->service->service_name, ziti_conn_source_identity(clt));
        switch (io_ctx->server_proto_id) {
            case IPPROTO_TCP:
                uv_read_start((uv_stream_t *) &io_ctx->server.tcp, alloc_buffer, on_hosted_tcp_server_data);
                break;
            case IPPROTO_UDP:
                uv_udp_recv_start(&io_ctx->server.udp, alloc_buffer, on_hosted_udp_server_data);
                break;
        }
    } else {
        ZITI_LOG(ERROR, "hosted_service[%s] client[%s] failed to connect: %s", io_ctx->service->service_name,
                 ziti_conn_source_identity(clt), ziti_errorstr(err));
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
    if (io_ctx == NULL) {
        ZITI_LOG(DEBUG, "null io_ctx");
        return;
    }
    if (status < 0) {
        ZITI_LOG(ERROR, "hosted_service[%s], client[%s]: connect to %s failed: %s", io_ctx->service->service_name,
                 ziti_conn_source_identity(io_ctx->client), io_ctx->server_dial_str, uv_strerror(status));
        ziti_close(&io_ctx->client);
        free(c);
        return;
    }
    ZITI_LOG(INFO, "hosted_service[%s], client[%s]: connected to server %s", io_ctx->service->service_name,
             ziti_conn_source_identity(io_ctx->client), io_ctx->server_dial_str);
    ziti_accept(io_ctx->client, on_hosted_client_connect_complete, on_hosted_client_data);
    free(c);
}

struct addrinfo_params_s {
    const char *    address;
    const char *    port;
    char            _port_str[12]; // buffer used when config type uses int for port
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
}

static const char *get_protocol_str(int protocol_id) {
    switch (protocol_id) {
        case IPPROTO_TCP:
            return "tcp";
        case IPPROTO_UDP:
            return "udp";
        default:
            return "NUL";
    }
}

static bool addrinfo_from_host_cfg_v1(struct addrinfo_params_s *dial_params, const ziti_host_cfg_v1 *config, model_map *app_data) {
    const char *dial_protocol_str = NULL;

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

    if (config->dial_intercepted_port) {
        dial_params->port = model_map_get(app_data, "intercepted_port");
        if (dial_params->port == NULL) {
            snprintf(dial_params->err, sizeof(dial_params->err),
                     "service config specifies 'dialInterceptedPort' but client didn't send intercepted port");
            return false;
        } else {
            errno = 0;
            strtol(dial_params->port, NULL, 10);
            if (errno != 0) {
                snprintf(dial_params->err, sizeof(dial_params->err),
                         "client sent invalid intercept port '%s'", dial_params->port);
                return false;
            }
        }
    } else {
        snprintf(dial_params->_port_str, sizeof(dial_params->_port_str), "%d", config->port);
        dial_params->port = dial_params->_port_str;
    }

    return true;
}

static bool addrinfo_from_server_cfg_v1(struct addrinfo_params_s *dial_params, const ziti_server_cfg_v1 *config, model_map *app_data) {
    dial_params->hints.ai_protocol = get_protocol_id(config->protocol);
    if (dial_params->hints.ai_protocol < 0) {
        snprintf(dial_params->err, sizeof(dial_params->err), "unsupported dial protocol '%s'", config->protocol);
        return false;
    }

    dial_params->address = config->hostname;

    snprintf(dial_params->_port_str, sizeof(dial_params->_port_str), "%d", config->port);
    dial_params->port = dial_params->_port_str;

    return true;
}

void set_dial_addr_from_addrinfo(struct hosted_io_ctx_s *io, struct addrinfo *ai) {

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

    struct addrinfo *dial_ai = NULL, *source_ai = NULL;
    struct hosted_io_ctx_s *io_ctx = NULL;
    bool err = false;

    char *app_data_json = ziti_conn_data(clt);
    tunneler_app_data app_data_model;
    if (app_data_json != NULL) {
        ZITI_LOG(DEBUG, "hosted_service[%s], client[%s]: received app_data_json='%s'", service_ctx->service_name,
                 client_identity, app_data_json);
        if (parse_tunneler_app_data(&app_data_model, app_data_json, strlen(app_data_json)) != 0) {
            ZITI_LOG(ERROR, "hosted_service[%s], client[%s]: failed to parse app_data_json '%s'",
                     service_ctx->service_name,
                     client_identity, app_data_json);
            err = true;
            goto done;
        }
    }

    struct addrinfo_params_s dial_ai_params;
    memset(&dial_ai_params, 0, sizeof(dial_ai_params));
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
            err = true;
            goto done;
    }

    if (!s) {
        ZITI_LOG(ERROR, "hosted_service[%s], client[%s]: failed to create dial addrinfo params: %s",
                 service_ctx->service_name, client_identity, dial_ai_params.err);
        err = true;
        goto done;
    }

    dial_ai_params.hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV;
    switch (dial_ai_params.hints.ai_protocol) {
        case IPPROTO_TCP:
            dial_ai_params.hints.ai_socktype = SOCK_STREAM;
            break;
        case IPPROTO_UDP:
            dial_ai_params.hints.ai_socktype = SOCK_DGRAM;
            break;
    }

    if ((s = getaddrinfo(dial_ai_params.address, dial_ai_params.port, &dial_ai_params.hints, &dial_ai)) != 0) {
        ZITI_LOG(ERROR, "hosted_service[%s], client[%s]: getaddrinfo(%s,%s) failed: %s",
                 service_ctx->service_name, client_identity, dial_ai_params.address, dial_ai_params.port, gai_strerror(s));
        err = true;
        goto done;
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
        const char *port_sep = strchr(source_ip, ':');
        const char *source_port = NULL;
        char source_ip_cp[64];
        if (port_sep != NULL) {
            source_port = port_sep + 1;
            strncpy(source_ip_cp, source_ip, port_sep-source_ip);
            source_ip_cp[port_sep-source_ip] = '\0';
            source_ip = source_ip_cp;
        }
        source_hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICHOST;
        source_hints.ai_protocol = dial_ai_params.hints.ai_protocol;
        source_hints.ai_socktype = dial_ai_params.hints.ai_socktype;
        if ((s = getaddrinfo(source_ip, source_port, &source_hints, &source_ai)) != 0) {
            ZITI_LOG(ERROR, "hosted_service[%s], client[%s]: getaddrinfo(%s,%s) failed: %s",
                     service_ctx->service_name, client_identity, source_ip, source_port, gai_strerror(s));
            err = true;
            goto done;
        }
        if (source_ai->ai_next != NULL) {
            ZITI_LOG(DEBUG, "hosted_service[%s], client[%s]: getaddrinfo(%s,%s) returned multiple results; using first",
                     service_ctx->service_name, client_identity, source_ip, source_port);
        }
    }

    io_ctx = calloc(1, sizeof(struct hosted_io_ctx_s));
    io_ctx->service = service_ctx;
    io_ctx->client = clt;
    io_ctx->server_proto_id = dial_ai->ai_protocol;

    char host[48];
    char port[12];
    s = getnameinfo(dial_ai->ai_addr, dial_ai->ai_addrlen, host, sizeof(host), port, sizeof(port),
                    NI_NUMERICHOST | NI_NUMERICSERV);
    if (s == 0) {
        snprintf(io_ctx->server_dial_str, sizeof(io_ctx->server_dial_str), "%s:%s:%s",
                 get_protocol_str(dial_ai->ai_protocol), host, port);
    } else {
        ZITI_LOG(WARN, "hosted_service[%s] client[%s] getnameinfo failed: %s", io_ctx->service->service_name,
                 ziti_conn_source_identity(io_ctx->client), gai_strerror(s));
        strncpy(io_ctx->server_dial_str, "<unknown>", sizeof(io_ctx->server_dial_str));
    }

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
                    ZITI_LOG(ERROR, "hosted_service[%s], client[%s]: uv_tcp_connect failed: %s",
                             service_ctx->service_name, client_identity, uv_err_name(uv_err));
                    err = true;
                    goto done;
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

done:
    if (err) {
        ziti_close(&clt);
        safe_free(io_ctx);
    }
    if (app_data_json != NULL) {
        free_tunneler_app_data(&app_data_model);
    }
    if (dial_ai != NULL) {
        freeaddrinfo(dial_ai);
    }
    if (source_ai != NULL) {
        freeaddrinfo(source_ai);
    }
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

static void listen_opts_from_host_cfg_v1(ziti_listen_opts *opts, const ziti_host_cfg_v1 *config) {
    tag *t;

    opts->bind_using_edge_identity = false;
    t = model_map_get(&config->listen_options, "bindUsingEdgeIdentity");
    if (t != NULL) {
        opts->bind_using_edge_identity = t->bool_value;
    }

    opts->identity = NULL;
    t = model_map_get(&config->listen_options, "identity");
    if (t != NULL) {
        if (opts->bind_using_edge_identity) {
            ZITI_LOG(WARN, "listen options specifies both 'identity=%s' and 'bindUsingEdgeIdentity=true'",
                     t->string_value);
        } else {
            opts->identity = t->string_value;
            // todo resolve $tunneler_id refs
        }
    }

    opts->connect_timeout_seconds = 5;
    t = model_map_get(&config->listen_options, "connectTimeoutSeconds");
    if (t != NULL) {
        opts->connect_timeout_seconds = t->num_value;
    }

    opts->terminator_precedence = PRECEDENCE_DEFAULT;
    t = model_map_get(&config->listen_options, "precedence");
    if (t != NULL) {
        if (strcmp(t->string_value, "default") == 0) {
            opts->terminator_precedence = PRECEDENCE_DEFAULT;
        } else if (strcmp(t->string_value, "required") == 0) {
            opts->terminator_precedence = PRECEDENCE_REQUIRED;
        } else if (strcmp(t->string_value, "failed") == 0) {
            opts->terminator_precedence = PRECEDENCE_FAILED;
        } else {
            ZITI_LOG(WARN, "unsupported terminator precedence '%s'", t->string_value);
        }
    }

    opts->terminator_cost = 0;
    t = model_map_get(&config->listen_options, "cost");
    if (t != NULL) {
        opts->terminator_cost = t->num_value;
    }
}

/** called by the tunneler sdk when a hosted service becomes available */
host_ctx_t *ziti_sdk_c_host(void *ziti_ctx, uv_loop_t *loop, const char *service_name, cfg_type_e cfg_type, const void *cfg) {
    if (service_name == NULL) {
        ZITI_LOG(ERROR, "null service_name");
        return NULL;
    }

    struct hosted_service_ctx_s *host_ctx = calloc(1, sizeof(struct hosted_service_ctx_s));
    host_ctx->service_name = strdup(service_name);
    host_ctx->ziti_ctx = ziti_ctx;
    host_ctx->loop = loop;
    host_ctx->cfg_type = cfg_type;
    host_ctx->cfg = cfg;

    char *display_proto = "?", *display_addr = "?", display_port[12] = { '?', '\0' };
    ziti_listen_opts listen_opts;
    ziti_listen_opts *listen_opts_p = NULL;
    switch (cfg_type) {
        case HOST_CFG_V1: {
            const ziti_host_cfg_v1 *host_v1_cfg = cfg;
            listen_opts_from_host_cfg_v1(&listen_opts, host_v1_cfg);
            listen_opts_p = &listen_opts;
            if (!host_v1_cfg->dial_intercepted_protocol) {
                display_proto = host_v1_cfg->protocol;
            }
            if (!host_v1_cfg->dial_intercepted_address) {
                display_addr = host_v1_cfg->address;
            }
            if (!host_v1_cfg->dial_intercepted_port) {
                snprintf(display_port, sizeof(display_port), "%d", host_v1_cfg->port);
            }
        }
            break;
        case SERVER_CFG_V1: {
            const ziti_server_cfg_v1 *server_v1_cfg = cfg;
            display_proto = server_v1_cfg->protocol;
            display_addr = server_v1_cfg->hostname;
            snprintf(display_port, sizeof(display_port), "%d", server_v1_cfg->port);
        }
            break;
        default:
            ZITI_LOG(WARN, "unexpected cfg_type %d", cfg_type);
            break;
    }

    snprintf(host_ctx->address, sizeof(host_ctx->address), "%s:%s:%s", display_proto, display_addr, display_port);
    ziti_connection serv;
    ziti_conn_init(ziti_ctx, &serv, host_ctx);

    ziti_listen_with_options(serv, service_name, listen_opts_p, hosted_listen_cb, on_hosted_client_connect);

    return host_ctx;
}

intercept_ctx_t *new_intercept_ctx(tunneler_context tnlr_ctx, const void *ziti_ctx, const char *service_name, cfg_type_e cfg_type, const void *cfg) {
    intercept_ctx_t *i_ctx = calloc(1, sizeof(intercept_ctx_t));
    int i;

    i_ctx->ziti_ctx = ziti_ctx;
    i_ctx->service_name = service_name;

    STAILQ_INIT(&i_ctx->protocols);
    STAILQ_INIT(&i_ctx->addresses);
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
                    intercept_ctx_add_protocol(i_ctx, config->protocols[i]);
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
    cfg_type_e cfgtype;
    cfg_alloc_fn alloc;
    cfg_free_fn free;
    cfg_parse_fn parse;
} cfgtype_desc_t;

#define CFGTYPE_DESC(name, cfgtype, type) { (name), (cfgtype), alloc_##type, free_##type, parse_##type }

static struct cfgtype_desc_s intercept_cfgtypes[] = {
        CFGTYPE_DESC("intercept.v1", INTERCEPT_CFG_V1, ziti_intercept_cfg_v1),
        CFGTYPE_DESC("ziti-tunneler-client.v1", CLIENT_CFG_V1, ziti_client_cfg_v1)
};

static struct cfgtype_desc_s host_cfgtypes[] = {
        CFGTYPE_DESC("host.v1", HOST_CFG_V1, ziti_host_cfg_v1),
        CFGTYPE_DESC("ziti-tunneler-server.v1", SERVER_CFG_V1, ziti_server_cfg_v1)
};

static tunneled_service_t current_tunneled_service;

/** set up intercept or host context according to service permissions and configuration */
tunneled_service_t *ziti_sdk_c_on_service(ziti_context ziti_ctx, ziti_service *service, int status, void *tnlr_ctx) {
    current_tunneled_service.intercept = NULL;
    current_tunneled_service.host = NULL;

    if (status == ZITI_OK) {
        int i, get_config_rc;
        cfgtype_desc_t *cfgtype;
        void *config;
        if (service->perm_flags & ZITI_CAN_DIAL) {
            for (i = 0; i < sizeof(intercept_cfgtypes) / sizeof(cfgtype_desc_t); i++) {
                cfgtype = &intercept_cfgtypes[i];
                config = cfgtype->alloc();
                get_config_rc = ziti_service_get_config(service, cfgtype->name, config, cfgtype->parse);
                if (get_config_rc == 0) {
                    intercept_ctx_t *i_ctx = new_intercept_ctx(tnlr_ctx, ziti_ctx, service->name, cfgtype->cfgtype, config);
                    ziti_tunneler_intercept(tnlr_ctx, i_ctx);
                    current_tunneled_service.intercept = i_ctx;
                    break;
                }
                cfgtype->free(config);
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
        ziti_tunneler_stop_intercepting(tnlr_ctx, ziti_ctx, service->name);
        // todo lookup intercept_ctx by name and free config
    }

    return &current_tunneled_service;
}