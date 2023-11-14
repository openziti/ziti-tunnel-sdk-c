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
#endif


#include <stdio.h>
#include <ziti/ziti_log.h>
#include <memory.h>
#include <ziti/ziti_tunnel_cbs.h>
#include "ziti_hosting.h"

#if _WIN32
#ifndef strcasecmp
#define strcasecmp(a,b) stricmp(a,b)
#endif
#endif

/********** hosting **********/
static void on_bridge_close(uv_handle_t *handle);

struct hosted_io_ctx_s {
    struct hosted_service_ctx_s *service;
    ziti_connection client;
    tunneler_app_data *app_data;
    char client_identity[80];
    const char *computed_dst_protocol;
    const char *computed_dst_ip_or_hn;
    const char *computed_dst_port;
    char resolved_dst[80];
    union {
        uv_tcp_t tcp;
        uv_udp_t udp;
    } server;
};

static void hosted_io_context_free(hosted_io_context io) {
    if (io) {
        if (io->app_data) {
            free_tunneler_app_data_ptr(io->app_data);
        }
        free(io);
    }
}

static void ziti_conn_close_cb(ziti_connection zc) {
    struct hosted_io_ctx_s *io_ctx = ziti_conn_data(zc);
    if (io_ctx) {
        ZITI_LOG(TRACE, "hosted_service[%s] client[%s] ziti_conn[%p] io[%p] closed",
                 io_ctx->service->service_name, io_ctx->client_identity, zc, io_ctx);
        hosted_io_context_free(io_ctx);
        ziti_conn_set_data(zc, NULL);
    } else {
        ZITI_LOG(TRACE, "ziti_conn[%p] is closed", zc);
    }
}

#define safe_free(p) if ((p) != NULL) free((p))

#define STAILQ_CLEAR(slist_head, free_fn) do { \
    while (!STAILQ_EMPTY(slist_head)) { \
        void *elem = STAILQ_FIRST(slist_head); \
        STAILQ_REMOVE_HEAD((slist_head), entries); \
        free_fn(elem); \
    } \
} while(0)

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

    if (hosted_ctx->forward_protocol) {
        STAILQ_CLEAR(&hosted_ctx->proto_u.allowed_protocols, safe_free);
    }

    if (hosted_ctx->forward_address) {
        STAILQ_CLEAR(&hosted_ctx->addr_u.allowed_addresses, safe_free);

        while(!LIST_EMPTY(&hosted_ctx->addr_u.allowed_hostnames)) {
            struct allowed_hostname_s *dns_entry = LIST_FIRST(&hosted_ctx->addr_u.allowed_hostnames);
            LIST_REMOVE(dns_entry, _next);
            safe_free(dns_entry->domain_name);
            safe_free(dns_entry);
        }
    }

    if (hosted_ctx->forward_port) {
        STAILQ_CLEAR(&hosted_ctx->port_u.allowed_port_ranges, safe_free);
    }

    STAILQ_CLEAR(&hosted_ctx->allowed_source_addresses, safe_free);
}

static void hosted_server_close_cb(uv_handle_t *handle) {
    struct hosted_io_ctx_s *io_ctx = handle->data;
    if (io_ctx->client) {
        ziti_close(io_ctx->client, ziti_conn_close_cb);
        ZITI_LOG(TRACE, "hosted_service[%s] client[%s] server_conn[%p] closed",
                 io_ctx->service->service_name, io_ctx->client_identity, handle);
    } else {
        ZITI_LOG(TRACE, "server_conn[%p] closed", handle);
        handle->data = NULL;
        safe_free(io_ctx);
    }
}

#define safe_close(h, cb) if(!uv_is_closing((uv_handle_t*)(h))) uv_close((uv_handle_t*)(h), cb)
static void hosted_server_close(struct hosted_io_ctx_s *io_ctx) {
    if (io_ctx == NULL) {
        return;
    }

    safe_close(&io_ctx->server, hosted_server_close_cb);
}

void *local_addr(uv_handle_t *h, struct sockaddr *name, int *len) {
    int err;

    if (h->type == UV_UDP) {
        uv_udp_t *udp = (uv_udp_t *) h;
        if ((err = uv_udp_getsockname(udp, name, len)) != 0) {
            ZITI_LOG(ERROR, "uv_udp_getsockname failed: %s (%d)", uv_strerror(err), err);
            return NULL;
        }
    } else if (h->type == UV_TCP) {
        uv_tcp_t *tcp = (uv_tcp_t *) h;
        if ((err = uv_tcp_getsockname(tcp, name, len)) != 0) {
            ZITI_LOG(ERROR, "uv_tcp_getsockname failed: %s (%d)", uv_strerror(err), err);
            return NULL;
        }
    } else {
        ZITI_LOG(ERROR, "unexpected uv handle type %d", h->type);
        return NULL;
    }

    return name;
}

/** called by ziti sdk when a client connection is established (or fails) */
static void on_hosted_client_connect_complete(ziti_connection clt, int err) {
    struct hosted_io_ctx_s *io_ctx = ziti_conn_data(clt);
    if (err == ZITI_OK) {
        uv_handle_t *server = (uv_handle_t *) &io_ctx->server.tcp;
        struct sockaddr_storage name_storage;
        struct sockaddr *name = (struct sockaddr *) &name_storage;
        int len = sizeof(name_storage);
        local_addr(server, name, &len);
        uv_getnameinfo_t req = {0};
        uv_getnameinfo(io_ctx->service->loop, &req, NULL, name, NI_NUMERICHOST|NI_NUMERICSERV);
        uv_os_fd_t fd;
        uv_fileno((uv_handle_t *) &io_ctx->server, &fd);
        ZITI_LOG(DEBUG, "hosted_service[%s] client[%s] local_addr[%s:%s] fd[%d] server[%s] connected %d", io_ctx->service->service_name,
                 io_ctx->client_identity, req.host, req.service, fd, io_ctx->resolved_dst, len);
        int rc = ziti_conn_bridge(clt, (uv_handle_t *) &io_ctx->server, on_bridge_close);
        if (rc != 0) {
            ZITI_LOG(ERROR, "failed to bridge client[%s] with hosted_service[%s]", io_ctx->client_identity, io_ctx->service->service_name);
            hosted_server_close(io_ctx);
        }
    } else {
        ZITI_LOG(ERROR, "hosted_service[%s] client[%s] failed to connect: %s", io_ctx->service->service_name,
                 io_ctx->client_identity, ziti_errorstr(err));
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
        // todo get out
    }
    struct hosted_io_ctx_s *io_ctx = c->handle->data;
    if (io_ctx->client == NULL) {
        ZITI_LOG(ERROR, "client closed before server connection was established");
        hosted_server_close(io_ctx);
        free(c);
        return;
    }

    if (status < 0) {
        ZITI_LOG(ERROR, "hosted_service[%s], client[%s]: connect to %s failed: %s", io_ctx->service->service_name,
                 io_ctx->client_identity, io_ctx->resolved_dst, uv_strerror(status));
        hosted_server_close(io_ctx);
        free(c);
        return;
    }
    ZITI_LOG(DEBUG, "hosted_service[%s], client[%s]: connected to server %s", io_ctx->service->service_name,
             io_ctx->client_identity, io_ctx->resolved_dst);
    ziti_accept(io_ctx->client, on_hosted_client_connect_complete, NULL);
    free(c);
}

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

static bool allowed_hostname_match(const char *hostname, const allowed_hostnames_t *hostnames) {
    struct allowed_hostname_s *entry;
    LIST_FOREACH(entry, hostnames, _next) {
        if (entry->domain_name[0] == '*') {
            for (char *dot = strchr(hostname, '.'); dot != NULL; dot = strchr(dot + 1, '.')) {
                if (strcmp(dot, entry->domain_name + 1) == 0) return true;
            }
        } else if (strcmp(hostname, entry->domain_name) == 0) {
            return true;
        }
    }
    return false;
}

static const char *compute_dst_protocol(const host_ctx_t *service, const tunneler_app_data *app_data,
                                        int *protocol_number, char *err, size_t err_sz) {
    const char *dst_proto;
    if (service->forward_protocol) {
        if (app_data == NULL || app_data->dst_protocol == NULL || app_data->dst_protocol[0] == '\0') {
            snprintf(err, err_sz, "config specifies 'forwardProtocol', but client didn't send %s in app_data",
                     DST_PROTO_KEY);
            return NULL;
        }
        if (!protocol_match(app_data->dst_protocol, &service->proto_u.allowed_protocols)) {
            snprintf(err, err_sz, "requested protocol '%s' is not in 'allowedProtocols", app_data->dst_protocol);
            return NULL;
        }
        dst_proto = app_data->dst_protocol;
    } else {
        dst_proto = service->proto_u.protocol;
    }

    if ((*protocol_number = get_protocol_id(app_data->dst_protocol)) < 0) {
        snprintf(err, err_sz, "requested protocol '%s' is not supported", app_data->dst_protocol);
        return NULL;
    }

    return dst_proto;
}

static const char *compute_dst_ip_or_hn(const host_ctx_t *service, const tunneler_app_data *app_data,
                                        bool *is_ip, char *err, size_t err_sz) {
    const char *ip_or_hn;
    bool ip_expected = false;
    bool hn_expected = false;
    if (service->forward_address) {
        if (app_data != NULL) {
            if (app_data->dst_hostname != NULL) {
                ZITI_LOG(VERBOSE, "using address from dst_hostname");
                ip_or_hn = app_data->dst_hostname;
                hn_expected = true;
            } else if (app_data->dst_ip != NULL) {
                ZITI_LOG(VERBOSE, "using address from dst_ip");
                ip_or_hn = app_data->dst_ip;
                ip_expected = true;
            } else {
                snprintf(err, err_sz, "config specifies 'forwardAddress', but client didn't send %s or %s in app_data",
                         DST_IP_KEY, DST_HOST_KEY);
                return NULL;
            }
        }
    } else {
        ZITI_LOG(VERBOSE, "using address from config");
        ip_or_hn = service->addr_u.address;
    }

    ziti_address dst;
    if (!ziti_address_from_string(&dst, ip_or_hn)) {
        snprintf(err, sizeof(err), "failed to parse %s", ip_or_hn);
        return NULL;
    }
    *is_ip = (dst.type == ziti_address_cidr);

    if (ip_expected && *is_ip == false) {
        ZITI_LOG(DEBUG, "client forwarded non-IP %s in dst_ip", ip_or_hn);
    }
    if (hn_expected && *is_ip == true) {
        ZITI_LOG(DEBUG, "client forwarded IP %s in dst_hostname", ip_or_hn);
    }

    // authorize address if forwarding
    if (service->forward_address) {
        if (dst.type == ziti_address_hostname) {
            if (!allowed_hostname_match(ip_or_hn, &service->addr_u.allowed_hostnames)) {
                snprintf(err, err_sz, "requested address '%s' is not in allowedAddresses",
                         app_data->dst_hostname);
                return NULL;
            }
        } else if (dst.type == ziti_address_cidr) {
            if (!address_match(&dst, &service->addr_u.allowed_addresses)) {
                snprintf(err, err_sz, "requested address '%s' is not in allowedAddresses", app_data->dst_ip);
                return NULL;
            }
        }
    }

    return ip_or_hn;
}

static const char *compute_dst_port(const host_ctx_t *service, const tunneler_app_data *app_data, char *err, size_t err_sz) {
    if (service->forward_port) {
        if (app_data == NULL || app_data->dst_port == NULL || app_data->dst_port[0] == '\0') {
            snprintf(err, err_sz, "config specifies 'forwardPort' but client didn't send %s in app_data", DST_PORT_KEY);
            return NULL;
        }
        errno = 0;
        int port = (int) strtol(app_data->dst_port, NULL, 10);
        if (errno != 0) {
            snprintf(err, err_sz, "invalid %s '%s' in app_data", DST_PORT_KEY, app_data->dst_port);
            return NULL;
        }
        if (!port_match(port, &service->port_u.allowed_port_ranges)) {
            snprintf(err, err_sz, "requested port '%s' is not in allowedPortRanges", app_data->dst_port);
            return NULL;
        }
        return app_data->dst_port;
    }

    static char port_from_config[12];
    snprintf(port_from_config, sizeof(port_from_config), "%d", service->port_u.port);
    return port_from_config;
}

static int do_bind(hosted_io_context io, const char *addr, int socktype) {
    // split out the ip and port if port was specified
    char *src_ip = strdup(io->app_data->source_addr);
    char *port = strchr(src_ip, ':');
    if (port != NULL) {
        *port = '\0';
        port++;
    }

    uv_getaddrinfo_t ai_req = {0};
    struct addrinfo hints = {0};
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    hints.ai_protocol = get_protocol_id(io->computed_dst_protocol);
    hints.ai_socktype = socktype;

    int uv_err = uv_getaddrinfo(io->service->loop, &ai_req, NULL, src_ip, port, &hints);
    free(src_ip);

    if (uv_err != 0) {
        ZITI_LOG(ERROR, "hosted_service[%s], client[%s]: getaddrinfo(%s) failed: %s",
                 io->service->service_name, io->client_identity, io->app_data->source_addr, uv_strerror(uv_err));
        return -1;
    }

    if (ai_req.addrinfo->ai_next != NULL) {
        ZITI_LOG(DEBUG, "hosted_service[%s], client[%s]: getaddrinfo(%s) returned multiple results; using first",
                 io->service->service_name, io->client_identity, io->app_data->source_addr);
    }

    ziti_address src_za;
    ziti_address_from_sockaddr(&src_za, ai_req.addrinfo->ai_addr); // convert for easy validation
    uv_freeaddrinfo(ai_req.addrinfo);

    if (!address_match(&src_za, &io->service->allowed_source_addresses)) {
        ZITI_LOG(ERROR, "hosted_service[%s], client[%s] client requested source IP %s is not allowed",
                 io->service->service_name, io->client_identity, io->app_data->source_addr);
        return -1;
    }

    switch (hints.ai_protocol) {
        case IPPROTO_TCP:
            uv_err = uv_tcp_bind(&io->server.tcp, ai_req.addrinfo->ai_addr, 0);
            break;
        case IPPROTO_UDP:
            uv_err = uv_udp_bind(&io->server.udp, ai_req.addrinfo->ai_addr, 0);
            break;
        default:
            ZITI_LOG(ERROR, "hosted_service[%s] client[%s] unsupported protocol %d when binding source address",
                     io->service->service_name, io->client_identity, hints.ai_protocol);
            return -1;
    }

    if (uv_err != 0) {
        ZITI_LOG(ERROR, "hosted_service[%s] client[%s]: bind failed: %s", io->service->service_name,
                 io->client_identity, uv_strerror(uv_err));
        return -1;
    }

    return 0;
}

static hosted_io_context hosted_io_context_new(struct hosted_service_ctx_s *service_ctx, ziti_connection client,
        tunneler_app_data *app_data, const char *dst_protocol, const char *dst_ip_or_hn, const char *dst_port) {
    hosted_io_context io = calloc(1, sizeof(struct hosted_io_ctx_s));
    io->service = service_ctx;

    // include underlay details in client identity if available
    if (app_data && app_data->src_protocol && app_data->src_ip && app_data->src_port) {
        snprintf(io->client_identity, sizeof(io->client_identity), "%s] client_src_addr[%s:%s:%s", ziti_conn_source_identity(client),
                 app_data->src_protocol, app_data->src_ip, app_data->src_port);
    } else {
        strncpy(io->client_identity, ziti_conn_source_identity(client), sizeof(io->client_identity));
    }
    io->computed_dst_protocol = dst_protocol;
    io->computed_dst_ip_or_hn = dst_ip_or_hn;
    io->computed_dst_port = dst_port;

    int socktype, uv_err = -1;
    int protocol_number = get_protocol_id(dst_protocol);
    switch (protocol_number) {
        case IPPROTO_TCP:
            uv_err = uv_tcp_init(service_ctx->loop, &io->server.tcp);
            socktype = SOCK_STREAM;
            io->server.tcp.data = io;
            break;
        case IPPROTO_UDP:
            uv_err = uv_udp_init(service_ctx->loop, &io->server.udp);
            socktype = SOCK_DGRAM;
            io->server.udp.data = io;
            break;
        default:
            ZITI_LOG(ERROR, "hosted_service[%s] client[%s] unsupported protocol '%s''", service_ctx->service_name,
                     io->client_identity, dst_protocol);
            free(io);
            return NULL;
    }
    if (uv_err != 0) {
        ZITI_LOG(ERROR, "hosted_service[%s] client[%s] dst[%s:%s:%s] failed to initialize underlay handle: %s",
                 service_ctx->service_name, io->client_identity, dst_protocol, dst_ip_or_hn, dst_port, uv_strerror(uv_err));
        free(io);
        return NULL;
    }
    // uv handle has been initialized and must be closed before freeing `io` now.

    // if app_data includes source ip[:port], verify that it is allowed before attempting to bind
    if (app_data && app_data->source_addr && app_data->source_addr[0] != '\0') {
        if (do_bind(io, app_data->source_addr, socktype) != 0) {
            hosted_server_close(io);
            return NULL;
        }
    }

    // success. now set references to ziti connection and app_data so cleanup happens in ziti_conn_close_cb
    io->client = client;
    io->app_data = app_data;

    return io;
}

static void on_hosted_client_connect_resolved(uv_getaddrinfo_t* req, int status, struct addrinfo* res);

/** called by ziti sdk when a ziti endpoint (client) initiates connection to a hosted service
 * - compute dial address (from appdata if forwarding, or from dial address in config)
 * - if forwarding, validate address is allowed
 * - validate src address if specified
 * - initiate async dns resolution of dial address (if computed address is hostname?)
 */
static void on_hosted_client_connect(ziti_connection serv, ziti_connection clt, int status, ziti_client_ctx *clt_ctx) {
    struct hosted_service_ctx_s *service_ctx = ziti_conn_data(serv);

    if (service_ctx == NULL) {
        ZITI_LOG(ERROR, "null service_ctx");
        ziti_close(clt, NULL);
        return;
    }

    if (status != ZITI_OK) {
        ZITI_LOG(ERROR, "hosted_service[%s] incoming connection failed: %s", service_ctx->service_name, ziti_errorstr(status));
        ziti_close(clt, NULL);
        return;
    }

    tunneler_app_data *app_data = NULL;
    if (clt_ctx->app_data != NULL) {
        ZITI_LOG(DEBUG, "hosted_service[%s] client[%s]: received app_data_json='%.*s'", service_ctx->service_name,
                 clt_ctx->caller_id, (int) clt_ctx->app_data_sz, clt_ctx->app_data);
        if (parse_tunneler_app_data_ptr(&app_data, (char *) clt_ctx->app_data, clt_ctx->app_data_sz) < 0) {
            ZITI_LOG(ERROR, "hosted_service[%s] client[%s]: failed to parse app_data_json '%.*s'",
                     service_ctx->service_name, clt_ctx->caller_id, (int) clt_ctx->app_data_sz, clt_ctx->app_data);
            ziti_close(clt, NULL);
            return;
        }
    }

    if (app_data != NULL && app_data->conn_type == TunnelConnectionTypes.resolver) {
        accept_resolver_conn(clt, &service_ctx->addr_u.allowed_hostnames);
        free_tunneler_app_data_ptr(app_data);
        return;
    }

    char err[80];
    int protocol_number;
    const char *protocol = compute_dst_protocol(service_ctx, app_data, &protocol_number, err, sizeof(err));
    if (protocol == NULL) {
        ZITI_LOG(ERROR, "hosted_service[%s] client[%s] failed to compute destination protocol: %s",
                 service_ctx->service_name, clt_ctx->caller_id, err);
        free_tunneler_app_data_ptr(app_data);
        ziti_close(clt, NULL);
        return;
    }

    bool is_ip;
    const char *ip_or_hn = compute_dst_ip_or_hn(service_ctx, app_data, &is_ip, err, sizeof(err));
    if (ip_or_hn == NULL) {
        ZITI_LOG(ERROR, "hosted_service[%s] client[%s] failed to compute destination address: %s",
                 service_ctx->service_name, clt_ctx->caller_id, err);
        free_tunneler_app_data_ptr(app_data);
        ziti_close(clt, NULL);
        return;
    }

    const char *port = compute_dst_port(service_ctx, app_data, err, sizeof(err));
    if (port == NULL) {
        ZITI_LOG(ERROR, "hosted_service[%s] client[%s] failed to compute destination port: %s",
                 service_ctx->service_name, clt_ctx->caller_id, err);
        free_tunneler_app_data_ptr(app_data);
        ziti_close(clt, NULL);
        return;
    }

    hosted_io_context io = hosted_io_context_new(service_ctx, clt, app_data, protocol, ip_or_hn, port);
    if (io == NULL) {
        ZITI_LOG(ERROR, "hosted_service[%s] client[%s] failed to create io context", service_ctx->service_name,
                 clt_ctx->caller_id);
        free_tunneler_app_data_ptr(app_data);
        ziti_close(clt, NULL);
        return;
    }

    ZITI_LOG(INFO, "hosted_service[%s] client[%s] dst_addr[%s:%s:%s]: incoming connection",
             service_ctx->service_name, io->client_identity, protocol, ip_or_hn, port);

    struct addrinfo hints = {0};
    hints.ai_protocol = protocol_number;
    hints.ai_socktype = protocol_number == IPPROTO_UDP ? SOCK_DGRAM : SOCK_STREAM;
    hints.ai_flags = AI_NUMERICSERV;
    if (is_ip) hints.ai_flags |= AI_NUMERICHOST;

    uv_getaddrinfo_t *ai_req = calloc(1, sizeof(uv_getaddrinfo_t));
    ai_req->data = io;
    ziti_conn_set_data(clt, io);

    int s = uv_getaddrinfo(service_ctx->loop, ai_req, on_hosted_client_connect_resolved, ip_or_hn, port, &hints);
    if (s != 0) {
        ZITI_LOG(ERROR, "hosted_service[%s] client[%s]: getaddrinfo(%s:%s:%s) failed: %s",
                 service_ctx->service_name, io->client_identity, protocol, ip_or_hn, port, uv_strerror(s));
        free(ai_req);
        hosted_server_close(io);
        return;
    }
}

static void on_hosted_client_connect_resolved(uv_getaddrinfo_t* ai_req, int status, struct addrinfo* res) {
    hosted_io_context io = ai_req->data;
    if (io == NULL) {
        ZITI_LOG(ERROR, "null io");
        if (status >= 0) uv_freeaddrinfo(res);
        free(ai_req);
        return;
    }

    if (status < 0) {
        ZITI_LOG(ERROR, "hosted_service[%s] client[%s] getaddrinfo(%s:%s:%s) failed: %s", io->service->service_name,
                 io->client_identity, io->computed_dst_protocol, io->computed_dst_ip_or_hn, io->computed_dst_port,
                 uv_strerror(status));
        free(ai_req);
        ZITI_LOG(DEBUG, "closing c[%p] io[%p]", io->client, ziti_conn_data(io->client));
        hosted_server_close(io);
        return;
    }

    if (res->ai_next != NULL) {
        ZITI_LOG(DEBUG, "hosted_service[%s], client[%s]: getaddrinfo(%s:%s:%s) returned multiple results; using first",
                 io->service->service_name, io->client_identity, io->computed_dst_protocol,
                 io->computed_dst_ip_or_hn, io->computed_dst_port);
    }

    uv_getnameinfo_t ni_req = {0};
    int uv_err = uv_getnameinfo(io->service->loop, &ni_req, NULL, res->ai_addr, NI_NUMERICHOST | NI_NUMERICSERV);
    if (uv_err == 0) {
        snprintf(io->resolved_dst, sizeof(io->resolved_dst), "%s:%s:%s",
                 get_protocol_str(res->ai_protocol), ni_req.host, ni_req.service);
    } else {
        ZITI_LOG(WARN, "hosted_service[%s] client[%s] getnameinfo failed: %s", io->service->service_name,
                 io->client_identity, uv_strerror(uv_err));
        strncpy(io->resolved_dst, "<unknown>", sizeof(io->resolved_dst));
    }

    ZITI_LOG(DEBUG, "hosted_service[%s] client[%s] initiating connection to %s",
             io->service->service_name, io->client_identity, io->resolved_dst);

    switch (res->ai_protocol) {
        case IPPROTO_TCP:
            {
                uv_connect_t *c = malloc(sizeof(uv_connect_t));
                uv_err = uv_tcp_connect(c, &io->server.tcp, res->ai_addr, on_hosted_tcp_server_connect_complete);
                if (uv_err != 0) {
                    ZITI_LOG(ERROR, "hosted_service[%s], client[%s]: uv_tcp_connect failed: %s",
                             io->service->service_name, io->client_identity, uv_strerror(uv_err));
                    hosted_server_close(io);
                }
            }
            break;
        case IPPROTO_UDP:
            uv_err = uv_udp_connect(&io->server.udp, res->ai_addr);
            if (uv_err != 0) {
                ZITI_LOG(ERROR, "hosted_service[%s], client[%s]: uv_udp_connect failed: %s",
                         io->service->service_name, io->client_identity, uv_strerror(uv_err));
                hosted_server_close(io);
            }
            if (ziti_accept(io->client, on_hosted_client_connect_complete, NULL) != ZITI_OK) {
                ZITI_LOG(ERROR, "ziti_accept failed");
                hosted_server_close(io);
            }
            break;
    }

    uv_freeaddrinfo(res);
    free(ai_req);
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
        ziti_close(serv, NULL);
        free_hosted_service_ctx(host_ctx);
    }
}

static ziti_listen_opts DEFAULT_LISTEN_OPTS = {
        .bind_using_edge_identity = false,
        .identity = NULL,
        .connect_timeout_seconds = 5,
        .terminator_precedence = PRECEDENCE_DEFAULT,
        .terminator_cost = 0,
};

static void listen_opts_from_host_cfg_v1(ziti_listen_opts *opts, const ziti_host_cfg_v1 *config) {
    *opts = DEFAULT_LISTEN_OPTS;

    if (config && config->listen_options) {
        opts->bind_using_edge_identity = config->listen_options->bind_with_identity;
        opts->identity = config->listen_options->identity;
        opts->connect_timeout_seconds = config->listen_options->connect_timeout_seconds;
        opts->terminator_cost = config->listen_options->cost;

        const char *prec = config->listen_options->precendence;
        if (prec) {
            if (strcmp(prec, "default") == 0) {
                opts->terminator_precedence = PRECEDENCE_DEFAULT;
            } else if (strcmp(prec, "required") == 0) {
                opts->terminator_precedence = PRECEDENCE_REQUIRED;
            } else if (strcmp(prec, "failed") == 0) {
                opts->terminator_precedence = PRECEDENCE_FAILED;
            } else {
                ZITI_LOG(WARN, "unsupported terminator precedence '%s'", prec);
            }
        }
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
            int i;

            host_ctx->forward_protocol = host_v1_cfg->forward_protocol;
            if (host_v1_cfg->forward_protocol) {
                STAILQ_INIT(&host_ctx->proto_u.allowed_protocols);
                string_array allowed_protos = host_v1_cfg->allowed_protocols;
                for (i = 0; allowed_protos != NULL && allowed_protos[i] != NULL; i++) {
                    protocol_t *p = calloc(1, sizeof(protocol_t));
                    p->protocol = strdup(allowed_protos[i]);
                    STAILQ_INSERT_TAIL(&host_ctx->proto_u.allowed_protocols, p, entries);
                }
                if (i == 0) {
                    ZITI_LOG(ERROR,
                             "hosted_service[%s] specifies 'forwardProtocol' with zero-length 'allowedProtocols'",
                             host_ctx->service_name);
                    free_hosted_service_ctx(host_ctx);
                    return NULL;
                }
            } else {
                host_ctx->proto_u.protocol = host_v1_cfg->protocol;
                display_proto = host_v1_cfg->protocol;
            }

            host_ctx->forward_address = host_v1_cfg->forward_address;
            if (host_v1_cfg->forward_address) {
                STAILQ_INIT(&host_ctx->addr_u.allowed_addresses);
                LIST_INIT(&host_ctx->addr_u.allowed_hostnames);

                ziti_address_array allowed_addrs = host_v1_cfg->allowed_addresses;
                for (i = 0; allowed_addrs != NULL && allowed_addrs[i] != NULL; i++) {
                    if (allowed_addrs[i]->type == ziti_address_hostname) {
                        ZITI_LOG(DEBUG, "hosted_service[%s] failed to parse allowed_address '%s' as IP address",
                                 host_ctx->service_name, allowed_addrs[i]->addr.hostname);
                        struct allowed_hostname_s *dns_entry = calloc(1, sizeof(struct allowed_hostname_s));
                        dns_entry->domain_name = strdup(allowed_addrs[i]->addr.hostname);
                        LIST_INSERT_HEAD(&host_ctx->addr_u.allowed_hostnames, dns_entry, _next);
                    } else if (allowed_addrs[i]->type == ziti_address_cidr) {
                        address_t *a = calloc(1, sizeof(address_t));
                        ziti_address_print(a->str, sizeof(a->str), allowed_addrs[i]);
                        memcpy(&a->za, allowed_addrs[i], sizeof(a->za));
                        STAILQ_INSERT_TAIL(&host_ctx->addr_u.allowed_addresses, a, entries);
                    } else {
                        ZITI_LOG(WARN, "unknown ziti_address type %d", allowed_addrs[i]->type);
                    }
                }
                if (i == 0) {
                    ZITI_LOG(ERROR, "hosted_service[%s] specifies 'forwardAddress' with zero-length 'allowedAddresses'",
                             host_ctx->service_name);
                    free_hosted_service_ctx(host_ctx);
                    return NULL;
                }
            } else {
                host_ctx->addr_u.address = host_v1_cfg->address;
                display_addr = host_v1_cfg->address;
            }

            host_ctx->forward_port = host_v1_cfg->forward_port;
            if (host_v1_cfg->forward_port) {
                STAILQ_INIT(&host_ctx->port_u.allowed_port_ranges);
                ziti_port_range_array port_ranges = host_v1_cfg->allowed_port_ranges;
                for (i = 0; port_ranges != NULL && port_ranges[i] != NULL; i++) {
                    port_range_t *pr = parse_port_range(port_ranges[i]->low, port_ranges[i]->high);
                    STAILQ_INSERT_TAIL(&host_ctx->port_u.allowed_port_ranges, pr, entries);
                }
                if (i == 0) {
                    ZITI_LOG(ERROR, "hosted_service[%s] specifies 'forwardPort' with zero-length 'allowedPortRanges'",
                             host_ctx->service_name);
                    free_hosted_service_ctx(host_ctx);
                }
            } else {
                host_ctx->port_u.port = host_v1_cfg->port;
                snprintf(display_port, sizeof(display_port), "%d", host_v1_cfg->port);
            }

            STAILQ_INIT(&host_ctx->allowed_source_addresses);
            ziti_address_array allowed_src_addrs = host_v1_cfg->allowed_source_addresses;
            for (i = 0; allowed_src_addrs != NULL && allowed_src_addrs[i] != NULL; i++) {
                if (allowed_src_addrs[i]->type != ziti_address_cidr) {
                    if (allowed_src_addrs[i]->type == ziti_address_hostname) {
                        ZITI_LOG(ERROR, "hosted_service[%s] cannot use hostname '%s' as `allowed_source_address`",
                                 host_ctx->service_name, allowed_src_addrs[i]->addr.hostname);
                    } else {
                        ZITI_LOG(ERROR, "unknown ziti_address type %d", allowed_src_addrs[i]->type);
                    }
                    free_hosted_service_ctx(host_ctx);
                    return NULL;
                }
                address_t *a = calloc(1, sizeof(address_t));
                ziti_address_print(a->str, sizeof(a->str), allowed_src_addrs[i]);
                memcpy(&a->za, allowed_src_addrs[i], sizeof(a->za));
                STAILQ_INSERT_TAIL(&host_ctx->allowed_source_addresses, a, entries);
            }
        }
            break;
        case SERVER_CFG_V1: {
            const ziti_server_cfg_v1 *server_v1_cfg = cfg;
            display_proto = server_v1_cfg->protocol;
            host_ctx->forward_protocol = false;
            host_ctx->proto_u.protocol = server_v1_cfg->protocol;

            display_addr = server_v1_cfg->hostname;
            host_ctx->forward_address = false;
            host_ctx->addr_u.address = server_v1_cfg->hostname;

            snprintf(display_port, sizeof(display_port), "%d", server_v1_cfg->port);
            host_ctx->forward_port = false;
            host_ctx->port_u.port = server_v1_cfg->port;
        }
            break;
        default:
            ZITI_LOG(WARN, "unexpected cfg_type %d", cfg_type);
            break;
    }

    snprintf(host_ctx->display_address, sizeof(host_ctx->display_address), "%s:%s:%s", display_proto, display_addr, display_port);
    ziti_connection serv;
    ziti_conn_init(ziti_ctx, &serv, host_ctx);

    char listen_identity[128];
    if (listen_opts_p != NULL) {
        if (listen_opts_p->identity != NULL && listen_opts_p->identity[0] != '\0') {
            const ziti_identity *zid = ziti_get_identity(ziti_ctx);
            strncpy(listen_identity, listen_opts_p->identity, sizeof(listen_identity));
            if (string_replace(listen_identity, sizeof(listen_identity), "$tunneler_id.name", zid->name) != NULL) {
                listen_opts_p->identity = listen_identity;
            }
        }
    }
    ziti_listen_with_options(serv, service_name, listen_opts_p, hosted_listen_cb, on_hosted_client_connect);

    return host_ctx;
}


static void on_uv_close(uv_handle_t *handle) {
    struct hosted_io_ctx_s *io_ctx = handle->data;
    hosted_io_context_free(io_ctx);
}

static void on_bridge_close(uv_handle_t *handle) {
    struct hosted_io_ctx_s *io_ctx = handle->data;
    uv_getnameinfo_t req = {0};
    if (io_ctx != NULL) {
        struct sockaddr_storage name_storage;
        struct sockaddr *name = (struct sockaddr *) &name_storage;
        int len = sizeof(name_storage);
        local_addr(handle, name, &len);
        uv_getnameinfo(io_ctx->service->loop, &req, NULL, name, NI_NUMERICHOST | NI_NUMERICSERV);
    }
    uv_os_fd_t fd;
    uv_fileno(handle, &fd);
    ZITI_LOG(DEBUG, "closing local_addr[%s:%s] fd[%d] ", req.host, req.service, fd);
    uv_close(handle, on_uv_close);
}
