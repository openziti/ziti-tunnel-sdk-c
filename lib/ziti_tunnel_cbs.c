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
    ziti_io_context *ziti_io_ctx = ziti_conn_data(conn);
    if (status == ZITI_OK) {
        ziti_tunneler_dial_completed(&ziti_io_ctx->tnlr_io_ctx, ziti_io_ctx, status == ZITI_OK);
    } else {
        ZITI_LOG(ERROR, "ziti dial failed: %s", ziti_errorstr(status));
        free(ziti_io_ctx);
    }
}

/** called by ziti SDK when ziti service has data for the client */
ssize_t on_ziti_data(ziti_connection conn, uint8_t *data, ssize_t len) {
    ziti_io_context *ziti_io_ctx = ziti_conn_data(conn);
    ZITI_LOG(TRACE, "got %zd bytes from ziti", len);
    if (ziti_io_ctx == NULL || ziti_io_ctx->tnlr_io_ctx == NULL) {
        ZITI_LOG(DEBUG, "null io_context - connection may have been closed already");
        ziti_conn_set_data(conn, NULL);
        ziti_close(&conn);
        free(ziti_io_ctx);
        return UV_ECONNABORTED;
    }
    if (len > 0) {
        int accepted = ziti_tunneler_write(&ziti_io_ctx->tnlr_io_ctx, data, len);
        if (accepted < 0) {
            ziti_sdk_c_close(ziti_io_ctx);
        }
        return accepted;
    } else if (len == ZITI_EOF) {
        ZITI_LOG(DEBUG, "ziti connection sent EOF (ziti_eof=%d, tnlr_eof=%d)", ziti_io_ctx->ziti_eof, ziti_io_ctx->tnlr_eof);
        ziti_io_ctx->ziti_eof = true;
        if (ziti_io_ctx->tnlr_eof) /* both sides are closed now */ {
            ziti_tunneler_close(&ziti_io_ctx->tnlr_io_ctx);
            ziti_conn_set_data(conn, NULL);
            free(ziti_io_ctx);
        } else {
            ziti_tunneler_close_write(&ziti_io_ctx->tnlr_io_ctx);
        }
    } else if (len < 0) {
        ZITI_LOG(ERROR, "ziti connection is closed due to [%zd](%s)", len, ziti_errorstr(len));
        ziti_tunneler_close(&ziti_io_ctx->tnlr_io_ctx);
        ziti_conn_set_data(conn, NULL);
        free(ziti_io_ctx);
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

static void tunneler_app_data_set_intercepted(tunneler_app_data *app_data, const char *intercepted) {
    if (app_data == NULL || intercepted == NULL) {
        ZITI_LOG(DEBUG, "null app_data or intercepted");
        return;
    }

}

/** render app_data as string (json) into supplied buffer. returns json string length. */
static size_t get_app_data_json(char *buf, size_t bufsz, tunneler_io_context io, const char *source_ip) {
    tunneler_app_data app_data;
    memset(&app_data, 0, sizeof(app_data));
    model_map_clear(&app_data.data, NULL);
    tag proto_tag, ip_tag, port_tag, source_ip_tag;
    const char *intercepted = get_intercepted_address(io);

    if (intercepted != NULL) {
        const char *proto_sep = strchr(intercepted, ':');
        proto_tag.type = tag_string;
        proto_tag.string_value = strndup(intercepted, proto_sep - intercepted);
        model_map_set(&app_data.data, "intercepted_protocol", &proto_tag);

        const char *ip_sep = strrchr(intercepted, ':');
        ip_tag.type = tag_string;
        ip_tag.string_value = strndup(proto_sep + 1, ip_sep - proto_sep);
        model_map_set(&app_data.data, "intercepted_address", &ip_tag);

        const char *port_str = ip_sep + 1;
        port_tag.type = tag_number;
        port_tag.num_value = (int) strtol(port_str, NULL, 10);
        model_map_set(&app_data.data, "intercepted_port", &port_tag);
    }

    if (source_ip != NULL) {
        source_ip_tag.type = tag_string;
        source_ip_tag.string_value = (char *) source_ip;
        model_map_set(&app_data.data, "source_ip", &source_ip_tag);
    }

    size_t json_len;
    if (json_from_tunneler_app_data(&app_data, buf, bufsz, &json_len) != 0) {
        ZITI_LOG(ERROR, "encoded app data length %ld bytes exceeds %ld byte limit ", json_len, sizeof(json));
        free_tunneler_app_data(&app_data);
        return 1;
    }

    return json_len;
}

static int dial_opts_from_client_cfg_v1(ziti_dial_opts *opts, const ziti_client_cfg_v1 *config, tunneler_io_context tnlr_io_ctx) {
}

/** initialize dial options from a ziti_intercept_cfg_v1 */
static int dial_opts_from_intercept_cfg_v1(ziti_dial_opts *opts, const ziti_intercept_cfg_v1 *config, tunneler_io_context tnlr_io_ctx) {
    model_map *dial_options_cfg = (model_map *)&config->dial_options;
    tag *t = (tag *) model_map_get(dial_options_cfg, "identity");
    if (t != NULL) {
        if (t->type == tag_string) {
            opts->identity = t->string_value; // todo strdup? t->string_value is allocated in ziti_intercept_cfg_v1.
        } else {
            ZITI_LOG(WARN, "dial_options.identity has non-string type %d", t->type);
        }
    }

    t = (tag *)model_map_get(dial_options_cfg, "connect_timeout_seconds");
    if (t != NULL) {
        if (t->type == tag_number) {
            opts->connect_timeout_seconds = t->num_value;
        } else {
            ZITI_LOG(WARN, "dial_options.connect_timeout_seconds has non-numeric type %d", t->type);
        }
    }

    return 0;
}

/** called by tunneler SDK after a client connection is intercepted */
void * ziti_sdk_c_dial(const intercept_ctx_t *intercept_ctx, tunneler_io_context tnlr_io_ctx) {
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
    ziti_io_ctx->tnlr_io_ctx = tnlr_io_ctx;

    ziti_context ziti_ctx = (ziti_context)intercept_ctx->ziti_ctx;
    if (ziti_conn_init(ziti_ctx, &ziti_io_ctx->ziti_conn, ziti_io_ctx) != ZITI_OK) {
        ZITI_LOG(ERROR, "ziti_conn_init failed");
        free(ziti_io_ctx);
        return NULL;
    }

    ziti_dial_opts dial_opts;
    memset(&dial_opts, 0, sizeof(dial_opts));
    char app_data_json[256];

    switch (intercept_ctx->cfg_type) {
        case CLIENT_CFG_V1:
            dial_opts_from_client_cfg_v1(&dial_opts, (ziti_client_cfg_v1 *)intercept_ctx->cfg, tnlr_io_ctx);
            dial_opts.app_data_sz = get_app_data_json(app_data_json, sizeof(app_data_json), tnlr_io_ctx, NULL);
            dial_opts.app_data = app_data_json;
            break;
        case INTERCEPT_CFG_V1:
            dial_opts_from_intercept_cfg_v1(&dial_opts, (ziti_intercept_cfg_v1 *)intercept_ctx->cfg, tnlr_io_ctx);
            dial_opts.app_data_sz = get_app_data_json(app_data_json, sizeof(app_data_json), tnlr_io_ctx, ((ziti_intercept_cfg_v1 *)intercept_ctx->cfg)->source_ip);
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
    safe_free(hosted_ctx->proto);
    safe_free(hosted_ctx->hostname);
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
    } else if (addr == NULL) {
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
        return;
    }
    ZITI_LOG(INFO, "connected to server for client %p: %p", c->handle->data, c);
    uv_read_start((uv_stream_t *) &io_ctx->server.tcp, alloc_buffer, on_hosted_tcp_server_data);
    ziti_accept(io_ctx->client, on_hosted_client_connect_complete, on_hosted_client_data);
}

/** called by ziti sdk when a ziti endpoint (client) initiates connection to a hosted service */
static void on_hosted_client_connect(ziti_connection serv, ziti_connection clt, int status) {
    struct hosted_service_ctx_s *service_ctx = ziti_conn_data(serv);

    if (service_ctx == NULL) {
        ZITI_LOG(ERROR, "null service_ctx");
        ziti_close(&clt);
        return;
    }

    struct addrinfo *ai, hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_ADDRCONFIG;   /* only return local IPs */
    hints.ai_flags |= AI_NUMERICSERV; /* we are supplying a numeric port; don't attempt to resolve servname */;
    hints.ai_protocol = service_ctx->proto_id;
    switch (service_ctx->proto_id) {
        case IPPROTO_TCP:
            hints.ai_socktype = SOCK_STREAM;
            break;
        case IPPROTO_UDP:
            hints.ai_socktype = SOCK_DGRAM;
            break;
        default:
            /* should not happen, since protocol is verified earlier */
            ZITI_LOG(ERROR, "unexpected protocol id %d for service %s", service_ctx->proto_id, service_ctx->service_name);
            return;
    }

    int s;
    char port_str[12];
    snprintf(port_str, sizeof(port_str), "%d", service_ctx->port);

    if ((s = getaddrinfo(service_ctx->hostname, port_str, &hints, &ai)) != 0) {
        ZITI_LOG(ERROR, "getaddrinfo(%s, %s) failed: %s", service_ctx->hostname, port_str, gai_strerror(s));
        return;
    }

    struct hosted_io_ctx_s *io_ctx = calloc(1, sizeof(struct hosted_io_ctx_s));
    io_ctx->service = service_ctx;
    io_ctx->client = clt;

    /* getaddrinfo returns a list of addrinfo structures that would normally be attempted in order
     * until one succeeds. We are implementing an async API, so probing is more complicated than
     * simple iteration. For now we use the first addrinfo in the list and hope for the best.
     */
    switch (ai->ai_protocol) {
        case IPPROTO_TCP: {
            uv_tcp_init(service_ctx->loop, &io_ctx->server.tcp);
            io_ctx->server.tcp.data = io_ctx;
            ziti_conn_set_data(clt, io_ctx);
            uv_connect_t *c = malloc(sizeof(uv_connect_t));
            uv_tcp_connect(c, &io_ctx->server.tcp, ai->ai_addr, on_hosted_tcp_server_connect_complete);
            }
            break;
        case IPPROTO_UDP: {
            uv_udp_init(service_ctx->loop, &io_ctx->server.udp);
            io_ctx->server.udp.data = io_ctx;
            ziti_conn_set_data(clt, io_ctx);
            uv_udp_connect(&io_ctx->server.udp, ai->ai_addr);
            uv_udp_recv_start(&io_ctx->server.udp, alloc_buffer, on_hosted_udp_server_data);
            ziti_accept(clt, on_hosted_client_connect_complete, on_hosted_client_data);
            }
            break;
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
            intercept_ctx_add_cidr(tnlr_ctx, i_ctx, ((ziti_client_cfg_v1 *)cfg)->hostname);
            intercept_ctx_add_port_range(i_ctx, ((ziti_client_cfg_v1 *)cfg)->port, ((ziti_client_cfg_v1 *)cfg)->port);
            break;
        case INTERCEPT_CFG_V1:
            {
                const ziti_intercept_cfg_v1 *config = cfg;
                for (i = 0; config->protocols[i] != NULL; i++) {
                    intercept_ctx_add_protocol(i_ctx, ((ziti_intercept_cfg_v1 *)cfg)->protocols[i]);
                }
                for (i = 0; config->addresses[i] != NULL; i++) {
                    intercept_ctx_add_cidr(tnlr_ctx, i_ctx, config->addresses[i]);
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

/** set up intercept or host context according to service permissions and configuration */
void ziti_sdk_c_on_service(ziti_context ziti_ctx, ziti_service *service, int status, void *tnlr_ctx) {
    if (status == ZITI_OK) {
        if (service->perm_flags & ZITI_CAN_DIAL) {
            /* look for intercept configurations. if one is found, resolve its addresses and add
             * add intercept context */
            int get_config_rc;
            {
                ziti_intercept_cfg_v1 config;
                get_config_rc = ziti_service_get_config(service, "intercept.v1", &config, parse_ziti_intercept_cfg_v1);
                if (get_config_rc == 0) {
                    intercept_ctx_t *i_ctx = new_intercept_ctx(tnlr_ctx, ziti_ctx, service->name, INTERCEPT_CFG_V1, &config);
                    ziti_tunneler_intercept(tnlr_ctx, i_ctx);
//                    free_ziti_intercept_cfg_v1(&config);
                }
            }
            {
                ziti_client_cfg_v1 config;
                get_config_rc = ziti_service_get_config(service, "ziti-tunneler-client.v1", &config, parse_ziti_client_cfg_v1);
                if (get_config_rc == 0) {
                    ZITI_LOG(INFO, "service_available: %s => %s:%d", service->name, config.hostname, config.port);
                    intercept_ctx_t *i_ctx = new_intercept_ctx(tnlr_ctx, ziti_ctx, service->name, CLIENT_CFG_V1, &config);
                    ziti_tunneler_intercept(tnlr_ctx, i_ctx);
//                    free_ziti_client_cfg_v1(&config);
                }
            }
        }
        if (service->perm_flags & ZITI_CAN_BIND) {
            ziti_server_cfg_v1 v1_config;
            int get_config_rc;
            get_config_rc = ziti_service_get_config(service, "ziti-tunneler-server.v1", &v1_config, parse_ziti_server_cfg_v1);
            if (get_config_rc == 0) {
                ZITI_LOG(INFO, "service_available: %s => %s:%s:%d", service->name, v1_config.protocol, v1_config.hostname, v1_config.port);
                ziti_tunneler_host_v1(tnlr_ctx, ziti_ctx, service->name, v1_config.protocol, v1_config.hostname, v1_config.port);
                free_ziti_server_cfg_v1(&v1_config);
            } else {
                ZITI_LOG(INFO, "service %s lacks ziti-tunneler-server.v1 config; not hosting", service->name);
            }
        }
    } else if (status == ZITI_SERVICE_UNAVAILABLE) {
        ZITI_LOG(INFO, "service unavailable: %s", service->name);
        ziti_tunneler_stop_intercepting(tnlr_ctx, ziti_ctx, service->name);
    }

}