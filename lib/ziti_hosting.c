/*
Copyright 2021 NetFoundry, Inc.

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
#endif


#include <stdio.h>
#include <ziti/ziti_log.h>
#include <memory.h>
#include "ziti/ziti_tunnel_cbs.h"

/********** hosting **********/


static void ziti_conn_close_cb(ziti_connection zc) {
    ZITI_LOG(TRACE, "ziti_conn[%p] is closed", zc);
    struct hosted_io_ctx_s *io_ctx = ziti_conn_data(zc);
    if (io_ctx) free(io_ctx);
}

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
    struct hosted_io_ctx_s *io_ctx = handle->data;
    if (io_ctx->client) {
        ziti_close(io_ctx->client, ziti_conn_close_cb);
    } else {
        free_hosted_io_ctx(handle->data);
    }
}

static void tcp_shutdown_cb(uv_shutdown_t *req, int res) {
    free(req);
}

static void hosted_server_close(struct hosted_io_ctx_s *io_ctx) {
    switch (io_ctx->service->proto_id) {
        case IPPROTO_TCP:
            uv_close((uv_handle_t *) &io_ctx->server.tcp, hosted_server_close_cb);
            break;
        case IPPROTO_UDP:
            uv_close((uv_handle_t *) &io_ctx->server.udp, hosted_server_close_cb);
            break;
    }
}

static void hosted_server_shutdown(struct hosted_io_ctx_s *io_ctx) {
    if (io_ctx->service->proto_id == IPPROTO_TCP) {
        uv_shutdown_t *shut = calloc(1, sizeof(uv_shutdown_t));
        uv_shutdown(shut, (uv_stream_t *) &io_ctx->server.tcp, tcp_shutdown_cb);
    }
}

/* called by ziti sdk when a client of a hosted service sends data */
static ssize_t on_hosted_client_data(ziti_connection clt, uint8_t *data, ssize_t len) {
    struct hosted_io_ctx_s *io_ctx = ziti_conn_data(clt);
    if (io_ctx == NULL) {
        ZITI_LOG(DEBUG, "null io");
        if (len > 0) {
            ZITI_LOG(DEBUG, "closing ziti connection");
            ziti_close(clt, ziti_conn_close_cb);
        }
        return 0;
    }

    if (len > 0) {
        char *copy = malloc(len);
        memcpy(copy, data, len);
        uv_buf_t buf = uv_buf_init(copy, len);
        switch (io_ctx->service->proto_id) {
            case IPPROTO_TCP: {
                uv_write_t *req = malloc(sizeof(uv_write_t));
                req->data = copy;
                int err = uv_write(req, (uv_stream_t *) &io_ctx->server.tcp, &buf, 1, on_hosted_tcp_client_write);
                if (err < 0) {
                    ZITI_LOG(ERROR, "uv_write failed: %s", uv_err_name(err));
                    on_hosted_tcp_client_write(req, err);
                }
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
        // client will not send more data, but should send one more message for connection closed.
        ZITI_LOG(INFO, "io %p sent EOF, ziti_eof=%d, tcp_eof=%d", io_ctx, io_ctx->ziti_eof, io_ctx->tcp_eof);
        io_ctx->ziti_eof = true;
        if (io_ctx->tcp_eof) {
            // server has also sent EOF, so close both sides now
            hosted_server_close(io_ctx);
        } else {
            // server can still send data, and ziti can still receive
            hosted_server_shutdown(io_ctx);
        }
    }
    else {
        ZITI_LOG(DEBUG, "client status %s. closing server connection", ziti_errorstr(len));
        hosted_server_close(io_ctx);
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
        uv_close((uv_handle_t *) stream, NULL);
        return;
    }

    if (nread > 0) {
        int zs = ziti_write(io_ctx->client, buf->base, nread, on_hosted_ziti_write, buf->base);
        if (zs != ZITI_OK) {
            ZITI_LOG(ERROR, "ziti_write to %s failed: %s", ziti_conn_source_identity(io_ctx->client),
                     ziti_errorstr(zs));
            on_hosted_ziti_write(io_ctx->client, nread, buf->base);
            // close both sides
            hosted_server_close(io_ctx);
        }
    } else {
        if (nread == UV_ENOBUFS) {
            ZITI_LOG(WARN, "tcp server is throttled: could not allocate buffer for incoming data [%zd](%s)", nread, uv_strerror(nread));
        } else if (nread == UV_EOF) {
            ZITI_LOG(INFO, "server sent FIN ziti_eof=%d, tcp_eof=%d, io=%p", io_ctx->ziti_eof, io_ctx->tcp_eof, io_ctx);
            io_ctx->tcp_eof = true;
            if (io_ctx->ziti_eof) {
                // ziti client has also sent EOF, so close both sides now
                hosted_server_close(io_ctx);
            } else {
                // server will not send more data, but ziti may.
                ziti_close_write(io_ctx->client);
                uv_read_stop((uv_stream_t *) &io_ctx->server.tcp);
            }
        } else {
            ZITI_LOG(WARN, "error reading from server [%zd](%s)", nread, uv_strerror(nread));
            hosted_server_close(io_ctx);
        }

        if (buf->base)
            free(buf->base);
    }
}

/** called by libuv when a hosted UDP server sends data to a client */
static void on_hosted_udp_server_data(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags) {
    struct hosted_io_ctx_s *io_ctx = handle->data;
    if (nread > 0) {
        int zs = ziti_write(io_ctx->client, buf->base, nread, on_hosted_ziti_write, buf->base);
        if (zs != ZITI_OK) {
            ZITI_LOG(ERROR, "ziti_write failed: %s", ziti_errorstr(zs));
            on_hosted_ziti_write(io_ctx->client, nread, buf->base);
            hosted_server_close(io_ctx);
        }
    } else if (addr == NULL && nread != 0) {
        if (buf->base != NULL) {
            free(buf->base);
        }
        ZITI_LOG(ERROR, "error receiving data from hosted service %s", io_ctx->service->service_name);
        hosted_server_close(io_ctx);
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
 *  c is the uv_tcp_connect_t that was initialized in on_hosted_client_connect
 *  c->handle is the uv_tcp_t (server stream) that was initialized in on_hosted_client_connect
 */
static void on_hosted_tcp_server_connect_complete(uv_connect_t *c, int status) {
    if (c == NULL || c->handle == NULL || c->handle->data == NULL) {
        ZITI_LOG(ERROR, "null handle or io_ctx");
    }
    struct hosted_io_ctx_s *io_ctx = c->handle->data;
    if (io_ctx->client == NULL) {
        ZITI_LOG(ERROR, "client closed before server connection was established");
        hosted_server_close(io_ctx);
        free(c);
        return;
    }

    if (status < 0) {
        ZITI_LOG(ERROR, "connect hosted service %s to %s:%s:%d failed: %s", io_ctx->service->service_name,
                 io_ctx->service->proto, io_ctx->service->hostname, io_ctx->service->port, uv_strerror(status));
        hosted_server_close(io_ctx);
        free(c);
        return;
    }
    ZITI_LOG(INFO, "connected to server for client %p(%p): %p", c->handle->data, c->data, c);
    ziti_accept(io_ctx->client, on_hosted_client_connect_complete, on_hosted_client_data);
    free(c);
}

/** called by ziti sdk when a ziti endpoint (client) initiates connection to a hosted service */
static void on_hosted_client_connect(ziti_connection serv, ziti_connection clt, int status, ziti_client_ctx *clt_ctx) {
    struct hosted_service_ctx_s *service_ctx = ziti_conn_data(serv);

    if (service_ctx == NULL) {
        ZITI_LOG(ERROR, "null service_ctx");
        ziti_close(clt, ziti_conn_close_cb);
        return;
    }

    struct addrinfo *ai, hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_ADDRCONFIG;   /* only return local IPs */
    hints.ai_flags |= AI_NUMERICSERV; /* we are supplying a numeric port; don't attempt to resolve servname */
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
            uv_connect_t *c = calloc(1, sizeof(uv_connect_t));
            c->data = clt;
            ZITI_LOG(DEBUG, "connecting to TCP(%s:%d) for client(%p)", service_ctx->hostname, service_ctx->port, clt);
            uv_tcp_connect(c, &io_ctx->server.tcp, ai->ai_addr, on_hosted_tcp_server_connect_complete);
            }
            break;
        case IPPROTO_UDP: {
            uv_udp_init(service_ctx->loop, &io_ctx->server.udp);
            io_ctx->server.udp.data = io_ctx;
            ziti_conn_set_data(clt, io_ctx);
            uv_udp_connect(&io_ctx->server.udp, ai->ai_addr);
            ziti_accept(clt, on_hosted_client_connect_complete, on_hosted_client_data);
            }
            break;
    }
    freeaddrinfo(ai);
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
        ziti_conn_set_data(serv, NULL);
        ziti_close(serv, ziti_conn_close_cb);
        free_hosted_service_ctx(host_ctx);
    }
}

/** called by the tunneler sdk when a hosted service becomes available */
void ziti_sdk_c_host_v1(void *ztx, uv_loop_t *loop, const char *service_name, const char *proto, const char *hostname, int port) {
    ziti_context ziti_ctx = ztx;
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
