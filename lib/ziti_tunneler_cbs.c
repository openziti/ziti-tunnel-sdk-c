#if _WIN32
// _WIN32_WINNT needs to be declared and needs to be > 0x600 in order for 
// some constants used below to be declared
#define _WIN32_WINNT  _WIN32_WINNT_WIN6
 // Windows Server 2008
#include <ws2tcpip.h>
#endif

#include <assert.h>
#include <stdio.h>
#include <ziti/ziti_log.h>
#include "ziti/ziti_tunneler_cbs.h"

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
        return len;
    }
    if (len > 0) {
        int accepted = ziti_tunneler_write(&ziti_io_ctx->tnlr_io_ctx, data, len);
        if (accepted < 0) {
            ziti_sdk_c_close(ziti_io_ctx);
        }
        return accepted;
    } else {
        ZITI_LOG(INFO, "ziti service closed connection");
        ziti_tunneler_close(&ziti_io_ctx->tnlr_io_ctx);
    }
    return len;
}

/** called by tunneler SDK after a client connection is closed */
void ziti_sdk_c_close(void *ziti_io_ctx) {
    ziti_io_context *_ziti_io_ctx = ziti_io_ctx;
    if (_ziti_io_ctx->ziti_conn != NULL) {
        ziti_close(&_ziti_io_ctx->ziti_conn);
    }
    //free(_ziti_io_ctx); // TODO don't know when it's OK to free this
}

/** called by tunneler SDK after a client connection is intercepted */
void * ziti_sdk_c_dial(const intercept_ctx_t *intercept_ctx, tunneler_io_context tnlr_io_ctx) {
    if (intercept_ctx == NULL) {
        ZITI_LOG(WARN, "null intercept_ctx");
        return NULL;
    }
    ZITI_LOG(VERBOSE, "ziti_dial(name=%s,id=%s)", intercept_ctx->service_name, intercept_ctx->service_id);

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

    if (ziti_dial(ziti_io_ctx->ziti_conn, intercept_ctx->service_name, on_ziti_connect, on_ziti_data) != ZITI_OK) {
        ZITI_LOG(ERROR, "ziti_dial failed");
        free(ziti_io_ctx);
        return NULL;
    }

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
                uv_write(req, (uv_stream_t *) io_ctx->server.tcp, &buf, 1, on_hosted_tcp_client_write);
                }
                break;
            case IPPROTO_UDP: {
                uv_udp_send_t *req = malloc(sizeof(uv_udp_send_t));
                req->data = copy;
                uv_udp_send(req, io_ctx->server.udp, &buf, 1, NULL, on_hosted_udp_client_write);
                }
                break;
            default:
                ZITI_LOG(ERROR, "invalid protocol %s in server config for service %s", io_ctx->service->proto, io_ctx->service->service_name);
                break;
        }
    }
    else if (len == ZITI_EOF) {
        switch (io_ctx->service->proto_id) {
            case IPPROTO_TCP:
                uv_close((uv_handle_t *)io_ctx->server.tcp, NULL);
                break;
            case IPPROTO_UDP:
                uv_close((uv_handle_t *)io_ctx->server.udp, NULL);
                break;
        }
    }
    else {
        ZITI_LOG(ERROR, "error: %zd(%s)", len, ziti_errorstr(len));
    }
    return len;
}

static void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    *buf = uv_buf_init((char*) malloc(suggested_size), suggested_size);
    /* TODO throttle based on pending requests */
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
        //free(buf->base); TODO free this here?
        return;
    }

    if (nread > 0) {
        ziti_write(io_ctx->client, buf->base, nread, on_hosted_ziti_write, buf->base);
    } else {
        ZITI_LOG(INFO, "stuff");
        ziti_close(&io_ctx->client);
    }
}

/** called by libuv when a hosted UDP server sends data to a client */
static void on_hosted_udp_server_data(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags) {
    struct hosted_io_ctx_s *io_ctx = handle->data;
    if (nread > 0) {
        ziti_write(io_ctx->client, buf->base, nread, on_hosted_ziti_write, buf->base);
    }
}

/**
 * called by libuv when a connection is established (or failed) with a TCP server
 *
 *  c is the uv_tcp_connect_t that was initialized in on_hosted_client_connect_complete
 *  c->handle is the uv_tcp_t (server stream) that was initialized in on_hosted_client_connect_complete
 */
static void on_hosted_tcp_server_connect_complete(uv_connect_t *c, int status) {
    if (status < 0) {
        ZITI_LOG(ERROR, "connection to server failed: %s", uv_strerror(status));
        return;
    }
    struct hosted_io_ctx_s *io_ctx = c->handle->data;
    ZITI_LOG(INFO, "connected to server for client %p: %p", c->handle->data, c);
    uv_read_start((uv_stream_t *) io_ctx->server.tcp, alloc_buffer, on_hosted_tcp_server_data);
}

/** called by ziti sdk when a client connection is established (or fails) */
static void on_hosted_client_connect_complete(ziti_connection clt, int status) {
    ZITI_LOG(INFO, "client %p connected to hosted service", clt);
    if (status == ZITI_OK) {
        struct hosted_service_ctx_s *service_ctx = ziti_conn_data(clt);
        if (service_ctx == NULL) {
            ZITI_LOG(DEBUG, "null service_ctx");
            ziti_close(&clt);
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
                uv_tcp_t *sock = malloc(sizeof(uv_tcp_t));
                uv_tcp_init(service_ctx->loop, sock);
                sock->data = io_ctx;
                io_ctx->server.tcp = sock;
                ziti_conn_set_data(clt, io_ctx);
                uv_connect_t *c = malloc(sizeof(uv_connect_t));
                uv_tcp_connect(c, sock, ai->ai_addr, on_hosted_tcp_server_connect_complete);
                }
                break;
            case IPPROTO_UDP: {
                uv_udp_t *sock = malloc(sizeof(uv_udp_t));
                uv_udp_init(service_ctx->loop, sock);
                sock->data = io_ctx;
                io_ctx->server.udp = sock;
                ziti_conn_set_data(clt, io_ctx);
                uv_udp_connect(sock, ai->ai_addr);
                uv_udp_recv_start(sock, alloc_buffer, on_hosted_udp_server_data);
                }
                break;
        }
    }
}

/** called by ziti sdk when a ziti endpoint (client) initiates connection to a hosted service */
static void on_hosted_client_connect(ziti_connection serv, ziti_connection client, int status) {
    struct hosted_service_ctx_s *service_ctx = ziti_conn_data(serv);
    ziti_conn_set_data(client, service_ctx);
    ziti_accept(client, on_hosted_client_connect_complete, on_hosted_client_data);
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
void ziti_sdk_c_host_v1(ziti_context ziti_ctx, uv_loop_t *loop, const char *service_name, const char *proto, const char *hostname, int port) {
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
    service_ctx->loop = loop;

    ziti_connection serv;
    ziti_conn_init(ziti_ctx, &serv, service_ctx);
    ziti_listen(serv, service_name, hosted_listen_cb, on_hosted_client_connect);
}