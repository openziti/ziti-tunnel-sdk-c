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
    char server_dial_str[64];
    union {
        uv_tcp_t tcp;
        uv_udp_t udp;
    } server;
};


static void ziti_conn_close_cb(ziti_connection zc) {
    struct hosted_io_ctx_s *io_ctx = ziti_conn_data(zc);
    if (io_ctx) {
        ZITI_LOG(TRACE, "hosted_service[%s] client[%s] ziti_conn[%p] closed",
                 io_ctx->service->service_name, ziti_conn_source_identity(zc), zc);
        free(io_ctx);
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
                 io_ctx->service->service_name, ziti_conn_source_identity(io_ctx->client), handle);
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
        uv_handle_t *server = (uv_handle_t *) &io_ctx->server;
        struct sockaddr_storage name_storage;
        struct sockaddr *name = (struct sockaddr *) &name_storage;
        int len = sizeof(name_storage);
        local_addr(server, name, &len);
        uv_getnameinfo_t req = {0};
        uv_getnameinfo(io_ctx->service->loop, &req, NULL, name, NI_NUMERICHOST|NI_NUMERICSERV);
        uv_os_fd_t fd;
        int e = uv_fileno((uv_handle_t *) &io_ctx->server, &fd);
        ZITI_LOG(DEBUG, "hosted_service[%s] client[%s] local_addr[%s:%s] fd[%d] server[%s] connected %d", io_ctx->service->service_name,
                 ziti_conn_source_identity(clt), req.host, req.service, fd, io_ctx->server_dial_str, len);
        int rc = ziti_conn_bridge(clt, (uv_handle_t *) &io_ctx->server, on_bridge_close);
        if (rc != 0) {
            ZITI_LOG(ERROR, "failed to bridge client[%s] with hosted_service[%s]", ziti_conn_source_identity(clt), io_ctx->service->service_name);
            hosted_server_close(io_ctx);
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
    if (io_ctx->client == NULL) {
        ZITI_LOG(ERROR, "client closed before server connection was established");
        hosted_server_close(io_ctx);
        free(c);
        return;
    }

    if (status < 0) {
        ZITI_LOG(ERROR, "hosted_service[%s], client[%s]: connect to %s failed: %s", io_ctx->service->service_name,
                 ziti_conn_source_identity(io_ctx->client), io_ctx->server_dial_str, uv_strerror(status));
        hosted_server_close(io_ctx);
        free(c);
        return;
    }
    ZITI_LOG(DEBUG, "hosted_service[%s], client[%s]: connected to server %s", io_ctx->service->service_name,
             ziti_conn_source_identity(io_ctx->client), io_ctx->server_dial_str);
    ziti_accept(io_ctx->client, on_hosted_client_connect_complete, NULL);
    free(c);
}

struct addrinfo_params_s {
    const char *    address;
    const char *    port;
    char            _port_str[12]; // buffer used when config type uses int for port
    struct addrinfo hints;
    char            err[128];
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

static bool addrinfo_from_host_ctx(struct addrinfo_params_s *dial_params, const host_ctx_t *host_ctx, tunneler_app_data *app_data) {
    const char *dial_protocol_str = NULL;

    if (host_ctx->forward_protocol) {
        dial_protocol_str = app_data->dst_protocol;
        if (dial_protocol_str == NULL | dial_protocol_str[0] == '\0') {
            snprintf(dial_params->err, sizeof(dial_params->err),
                     "hosted_service[%s] config specifies 'forwardProtocol', but client didn't send %s",
                     host_ctx->service_name, DST_PROTO_KEY);
            return false;
        }
        if (!protocol_match(app_data->dst_protocol, &host_ctx->proto_u.allowed_protocols)) {
            snprintf(dial_params->err, sizeof(dial_params->err),
                     "hosted_service[%s] client requested protocol '%s' is not allowed", host_ctx->service_name,
                     app_data->dst_protocol);
            return false;
        }
        dial_protocol_str = app_data->dst_protocol;
    } else {
        dial_protocol_str = host_ctx->proto_u.protocol;
    }

    dial_params->hints.ai_protocol = get_protocol_id(dial_protocol_str);
    if (dial_params->hints.ai_protocol < 0) {
        snprintf(dial_params->err, sizeof(dial_params->err), "unsupported %s '%s'", DST_PROTO_KEY, dial_protocol_str);
        return false;
    }

    if (host_ctx->forward_address) {
        if (app_data->dst_hostname != NULL && app_data->dst_hostname[0] != 0) {
            if (!allowed_hostname_match(app_data->dst_hostname, &host_ctx->addr_u.allowed_hostnames)) {
                snprintf(dial_params->err, sizeof(dial_params->err),
                         "hosted_service[%s] client requested address '%s' is not allowed", host_ctx->service_name,
                         app_data->dst_hostname);
                return false;
            }

            dial_params->address = app_data->dst_hostname;
            dial_params->hints.ai_flags = AI_ADDRCONFIG;
        } else if (app_data->dst_ip != NULL && app_data->dst_ip[0] != 0) {
            uv_getaddrinfo_t gai_req = {0};
            int s;
            if((s = uv_getaddrinfo(host_ctx->loop, &gai_req, NULL, app_data->dst_ip,
                                   app_data->dst_port, &dial_params->hints)) != 0) {
                ZITI_LOG(ERROR, "hosted_service[%s],getaddrinfo(%s,%s) failed: %s",
                        host_ctx->service_name, app_data->dst_ip, app_data->dst_port, gai_strerror(s));
                if (gai_req.addrinfo != NULL) {
                    uv_freeaddrinfo(gai_req.addrinfo);
                }
                return false;
            }
            ziti_address dst;
            ziti_address_from_sockaddr(&dst, gai_req.addrinfo->ai_addr);
            if (!address_match(&dst, &host_ctx->addr_u.allowed_addresses)) {
                ZITI_LOG(ERROR, "hosted_service[%s] client requested address '%s' is not allowed",
                         host_ctx->service_name,app_data->dst_ip);
                if (gai_req.addrinfo != NULL) {
                   uv_freeaddrinfo(gai_req.addrinfo);
                }
                return false;
            }
            if (gai_req.addrinfo != NULL) {
               uv_freeaddrinfo(gai_req.addrinfo);
            }
            dial_params->address = app_data->dst_ip;
            dial_params->hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV;
        } else {
            snprintf(dial_params->err, sizeof(dial_params->err),
                     "hosted_service[%s] config specifies 'forwardAddress' but client didn't send %s or %s",
                     host_ctx->service_name, DST_HOST_KEY, DST_IP_KEY);
            return false;
        }
    } else {
        dial_params->address = host_ctx->addr_u.address;
    }

    if (host_ctx->forward_port) {
        if (app_data->dst_port == NULL) {
            snprintf(dial_params->err, sizeof(dial_params->err),
                     "hosted_service[%s] config specifies 'forwardPort' but client didn't send %s",
                     host_ctx->service_name, DST_PORT_KEY);
            return false;
        }

        errno = 0;
        int port = (int) strtol(app_data->dst_port, NULL, 10);
        if (errno != 0) {
            snprintf(dial_params->err, sizeof(dial_params->err),
                     "hosted_service[%s] client sent invalid %s '%s'", host_ctx->service_name,
                     DST_PORT_KEY, app_data->dst_port);
            return false;
        }

        if (!port_match(port, &host_ctx->port_u.allowed_port_ranges)) {
            snprintf(dial_params->err, sizeof(dial_params->err),
                     "hosted_service[%s] client requested port '%s' is not allowed", host_ctx->service_name,
                     app_data->dst_port);
            return false;
        }
        dial_params->port = app_data->dst_port;
    } else {
        snprintf(dial_params->_port_str, sizeof(dial_params->_port_str), "%d", host_ctx->port_u.port);
        dial_params->port = dial_params->_port_str;
    }

    return true;
}

/** called by ziti sdk when a ziti endpoint (client) initiates connection to a hosted service */
static void on_hosted_client_connect(ziti_connection serv, ziti_connection clt, int status, ziti_client_ctx *clt_ctx) {
    struct hosted_service_ctx_s *service_ctx = ziti_conn_data(serv);

    if (service_ctx == NULL) {
        ZITI_LOG(ERROR, "null service_ctx");
        ziti_close(clt, ziti_conn_close_cb);
        return;
    }

    if (status != ZITI_OK) {
        ZITI_LOG(ERROR, "incoming connection to service[%s] failed: %s", service_ctx->service_name, ziti_errorstr(status));
        ziti_close(clt, ziti_conn_close_cb);
        return;
    }

    const char *client_identity = clt_ctx->caller_id;
    if (client_identity == NULL) client_identity = "<unidentified>";

    uv_getaddrinfo_t dial_ai_req = {0};
    uv_getaddrinfo_t source_ai_req = {0};
    struct hosted_io_ctx_s *io_ctx = NULL;
    bool err = false;

    tunneler_app_data app_data;
    memset(&app_data, 0, sizeof(app_data));
    if (clt_ctx->app_data != NULL) {
        ZITI_LOG(DEBUG, "hosted_service[%s], client[%s]: received app_data_json='%.*s'", service_ctx->service_name,
                 client_identity, (int)clt_ctx->app_data_sz, clt_ctx->app_data);
        if (parse_tunneler_app_data(&app_data, (char *)clt_ctx->app_data, clt_ctx->app_data_sz) < 0) {
            ZITI_LOG(ERROR, "hosted_service[%s], client[%s]: failed to parse app_data_json '%.*s'",
                     service_ctx->service_name,
                     client_identity, (int)clt_ctx->app_data_sz, clt_ctx->app_data);
            err = true;
            goto done;
        }
    }

    if (app_data.conn_type == TunnelConnectionTypes.resolver) {
        accept_resolver_conn(clt, &service_ctx->addr_u.allowed_hostnames);
        free_tunneler_app_data(&app_data);
        return;
    }

    struct addrinfo_params_s dial_ai_params;
    memset(&dial_ai_params, 0, sizeof(dial_ai_params));
    int s = addrinfo_from_host_ctx(&dial_ai_params, service_ctx, &app_data);
    if (!s) {
        ZITI_LOG(ERROR, "hosted_service[%s], client[%s]: failed to create dial addrinfo params: %s",
                 service_ctx->service_name, client_identity, dial_ai_params.err);
        err = true;
        goto done;
    }

    switch (dial_ai_params.hints.ai_protocol) {
        case IPPROTO_TCP:
            dial_ai_params.hints.ai_socktype = SOCK_STREAM;
            break;
        case IPPROTO_UDP:
            dial_ai_params.hints.ai_socktype = SOCK_DGRAM;
            break;
    }

    if ((s = uv_getaddrinfo(service_ctx->loop, &dial_ai_req, NULL, dial_ai_params.address, dial_ai_params.port, &dial_ai_params.hints)) != 0) {
        ZITI_LOG(ERROR, "hosted_service[%s], client[%s]: getaddrinfo(%s,%s) failed: %s",
                 service_ctx->service_name, client_identity, dial_ai_params.address, dial_ai_params.port, gai_strerror(s));
        err = true;
        goto done;
    }
    if (dial_ai_req.addrinfo->ai_next != NULL) {
        ZITI_LOG(DEBUG, "hosted_service[%s], client[%s]: getaddrinfo(%s,%s) returned multiple results; using first",
                 service_ctx->service_name, client_identity, dial_ai_params.address, dial_ai_params.port);
    }

    const char *dst_proto = app_data.dst_protocol;
    const char *dst_ip = app_data.dst_hostname ? app_data.dst_hostname : app_data.dst_ip;
    const char *dst_port = app_data.dst_port;
    if (dst_proto != NULL && dst_ip != NULL && dst_port != NULL) {
        ZITI_LOG(INFO, "hosted_service[%s], client[%s] dst_addr[%s:%s:%s]: incoming connection",
                 service_ctx->service_name, client_identity, dst_proto, dst_ip, dst_port);
    } else {
        ZITI_LOG(INFO, "hosted_service[%s], client[%s] incoming connection",
                 service_ctx->service_name, client_identity);
    }

    const char *source_addr = app_data.source_addr;
    if (source_addr != NULL && *source_addr != 0) {
        struct addrinfo source_hints = {0};
        const char *port_sep = strchr(source_addr, ':');
        const char *source_port = NULL;
        char source_ip_cp[64];
        if (port_sep != NULL) {
            source_port = port_sep + 1;
            strncpy(source_ip_cp, source_addr, port_sep - source_addr);
            source_ip_cp[port_sep - source_addr] = '\0';
            source_addr = source_ip_cp;
        }
        source_hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICHOST | AI_NUMERICSERV;
        source_hints.ai_protocol = dial_ai_params.hints.ai_protocol;
        source_hints.ai_socktype = dial_ai_params.hints.ai_socktype;
        if ((s = uv_getaddrinfo(service_ctx->loop, &source_ai_req, NULL, source_addr, source_port, &source_hints)) != 0) {
            ZITI_LOG(ERROR, "hosted_service[%s], client[%s]: getaddrinfo(%s,%s) failed: %s",
                     service_ctx->service_name, client_identity, source_addr, source_port, gai_strerror(s));
            err = true;
            goto done;
        }
        if (source_ai_req.addrinfo->ai_next != NULL) {
            ZITI_LOG(DEBUG, "hosted_service[%s], client[%s]: getaddrinfo(%s,%s) returned multiple results; using first",
                     service_ctx->service_name, client_identity, source_addr, source_port);
        }
        ziti_address src_za;
        ziti_address_from_sockaddr(&src_za, source_ai_req.addrinfo->ai_addr);
        if (!address_match(&src_za, &service_ctx->allowed_source_addresses)) {
            ZITI_LOG(ERROR, "hosted_service[%s], client[%s] client requested source IP %s is not allowed",
                     service_ctx->service_name, client_identity, source_addr);
            err = true;
            goto done;
        }
    }

    io_ctx = calloc(1, sizeof(struct hosted_io_ctx_s));
    io_ctx->service = service_ctx;
    io_ctx->client = clt;
    ziti_conn_set_data(clt, io_ctx);

    char host[48];
    char port[12];
    s = getnameinfo(dial_ai_req.addrinfo->ai_addr, dial_ai_req.addrinfo->ai_addrlen, host, sizeof(host), port, sizeof(port),
                    NI_NUMERICHOST | NI_NUMERICSERV);
    if (s == 0) {
        snprintf(io_ctx->server_dial_str, sizeof(io_ctx->server_dial_str), "%s:%s:%s",
                 get_protocol_str(dial_ai_req.addrinfo->ai_protocol), host, port);
    } else {
        ZITI_LOG(WARN, "hosted_service[%s] client[%s] getnameinfo failed: %s", io_ctx->service->service_name,
                 ziti_conn_source_identity(io_ctx->client), gai_strerror(s));
        strncpy(io_ctx->server_dial_str, "<unknown>", sizeof(io_ctx->server_dial_str));
    }

    int uv_err;
    switch (dial_ai_req.addrinfo->ai_protocol) {
        case IPPROTO_TCP:
            uv_tcp_init(service_ctx->loop, &io_ctx->server.tcp);
            io_ctx->server.tcp.data = io_ctx;
            if (source_ai_req.addrinfo != NULL) {
                uv_err = uv_tcp_bind(&io_ctx->server.tcp, source_ai_req.addrinfo->ai_addr, 0);
                if (uv_err != 0) {
                    ZITI_LOG(ERROR, "hosted_service[%s], client[%s]: uv_tcp_bind failed: %s",
                             service_ctx->service_name, client_identity, uv_err_name(uv_err));
                    err = true;
                    goto done;
                }
            }
            {
                uv_connect_t *c = malloc(sizeof(uv_connect_t));
                uv_err = uv_tcp_connect(c, &io_ctx->server.tcp, dial_ai_req.addrinfo->ai_addr, on_hosted_tcp_server_connect_complete);
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
            if (source_ai_req.addrinfo != NULL) {
                uv_err = uv_udp_bind(&io_ctx->server.udp, source_ai_req.addrinfo->ai_addr, 0);
                if (uv_err != 0) {
                    ZITI_LOG(ERROR, "hosted_service[%s] client[%s]: uv_udp_bind failed: %s",
                             service_ctx->service_name, client_identity, uv_err_name(uv_err));
                    err = true;
                    goto done;
                }
            }
            uv_err = uv_udp_connect(&io_ctx->server.udp, dial_ai_req.addrinfo->ai_addr);
            if (uv_err != 0) {
                ZITI_LOG(ERROR, "hosted_service[%s], client[%s]: uv_udp_connect failed: %s",
                         service_ctx->service_name, client_identity, uv_err_name(uv_err));
                err = true;
                goto done;
            }
            if (ziti_accept(clt, on_hosted_client_connect_complete, NULL) != ZITI_OK) {
                ZITI_LOG(ERROR, "ziti_accept failed");
                err = true;
                goto done;
            }
            break;
    }

    done:
    if (err) {
        if (io_ctx == NULL) {
            // if we get an error before creating io_ctx, just close incoming connection
            ziti_close(clt, ziti_conn_close_cb);
        } else {
            hosted_server_close(io_ctx);
        }
    }
    if (clt_ctx->app_data != NULL) {
        free_tunneler_app_data(&app_data);
    }
    if (dial_ai_req.addrinfo != NULL) {
        uv_freeaddrinfo(dial_ai_req.addrinfo);
    }
    if (source_ai_req.addrinfo != NULL) {
        uv_freeaddrinfo(source_ai_req.addrinfo);
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
        ziti_conn_set_data(serv, NULL);
        ziti_close(serv, ziti_conn_close_cb);
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
    free(io_ctx);
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
