/*
Copyright 2019-2020 NetFoundry, Inc.

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

// something wrong with lwip_xxxx byteorder functions
#ifdef _WIN32
#define LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS 1
#endif

#if defined(__mips) || defined(__mips__)
#define LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS 1
#endif

#include "lwip/init.h"
#include "lwip/raw.h"
#include "lwip/timeouts.h"
#include "netif_shim.h"
#include "ziti/ziti_tunnel.h"
#include "ziti_tunnel_priv.h"
#include "intercept.h"
#include "tunnel_tcp.h"
#include "tunnel_udp.h"
#include "uv.h"
#include "ziti/ziti_log.h"

#include <string.h>

static void run_packet_loop(uv_loop_t *loop, tunneler_context tnlr_ctx);

tunneler_context ziti_tunneler_init(tunneler_sdk_options *opts, uv_loop_t *loop) {
    init_debug();
    ZITI_LOG(INFO, "Ziti Tunneler SDK (%s)", ziti_tunneler_version());

    if (opts == NULL) {
        ZITI_LOG(ERROR, "invalid tunneler options");
        return NULL;
    }

    struct tunneler_ctx_s *ctx = calloc(1, sizeof(struct tunneler_ctx_s));
    if (ctx == NULL) {
        ZITI_LOG(ERROR, "failed to allocate tunneler context");
        return NULL;
    }
    ctx->loop = loop;
    memcpy(&ctx->opts, opts, sizeof(ctx->opts));
    run_packet_loop(loop, ctx);

    return ctx;
}

/** called by tunneler application when data has been successfully written to ziti */
void ziti_tunneler_ack(struct write_ctx_s *write_ctx) {
    write_ctx->ack(write_ctx);
    free(write_ctx);
}

const char *get_intercepted_address(const struct tunneler_io_ctx_s * tnlr_io) {
    if (tnlr_io == NULL) {
        return NULL;
    }
    return tnlr_io->intercepted;
}

void free_tunneler_io_context(tunneler_io_context *tnlr_io_ctx) {
    if (tnlr_io_ctx == NULL) {
        return;
    }

    if (*tnlr_io_ctx != NULL) {
        free(*tnlr_io_ctx);
        *tnlr_io_ctx = NULL;
    }
}

/**
 * called by tunneler application when a service dial has completed
 * - let the client know that we have a connection (e.g. send SYN/ACK)
 */
void ziti_tunneler_dial_completed(tunneler_io_context *tnlr_io_ctx, void *ziti_io_ctx, bool ok) {
    const char *status = ok ? "succeeded" : "failed";
    ZITI_LOG(INFO, "ziti dial %s: service=%s, client=%s", status, (*tnlr_io_ctx)->service_name, (*tnlr_io_ctx)->client);

    switch ((*tnlr_io_ctx)->proto) {
        case tun_tcp:
            tunneler_tcp_dial_completed(tnlr_io_ctx, ziti_io_ctx, ok);
            break;
        case tun_udp:
            tunneler_udp_dial_completed(tnlr_io_ctx, ziti_io_ctx, ok);
            break;
        default:
            ZITI_LOG(ERROR, "unknown proto %d", (*tnlr_io_ctx)->proto);
            break;
    }
}

int ziti_tunneler_host_v1(tunneler_context tnlr_ctx, const void *ziti_ctx, const char *service_name, const char *protocol, const char *hostname, int port) {
    tnlr_ctx->opts.ziti_host_v1((void *) ziti_ctx, tnlr_ctx->loop, service_name, protocol, hostname, port);
    ZITI_LOG(INFO, "hosting service %s at %s:%s:%d", service_name, protocol, hostname, port);
    return 0;
}

void ziti_tunneler_set_dns(tunneler_context tnlr_ctx, dns_manager *dns) {
    tnlr_ctx->dns = dns;
}

void intercept_ctx_add_protocol(intercept_ctx_t *ctx, const char *protocol) {
    protocol_t *proto = calloc(1, sizeof(protocol_t));
    proto->protocol = strdup(protocol);
    STAILQ_INSERT_TAIL(&ctx->protocols, proto, entries);
}

void intercept_ctx_add_cidr(tunneler_context tnlr_ctx, intercept_ctx_t *i_ctx, const char *cidr_str) {
    cidr_t *cidr = calloc(1, sizeof(cidr_t));
    bool failed = false;
    const char *prefix_sep = strchr(cidr_str, '/');
    const char *ip_str = cidr_str;

    if (prefix_sep != NULL) {
        ip_str = strndup(cidr_str, prefix_sep - cidr_str);
        cidr->prefix_len = (int)strtol(prefix_sep+1, NULL, 10);
    }

    if (ipaddr_aton(ip_str, &cidr->ip) == 0) {
        // does not parse as IP address; assume hostname and try to get IP from the dns manager
        if (tnlr_ctx->dns) {
            const char *resolved_ip_str = assign_ip(ip_str);
            if (tnlr_ctx->dns->apply(tnlr_ctx->dns, ip_str, resolved_ip_str) != 0) {
                ZITI_LOG(ERROR, "failed to apply DNS mapping for service[%s]: %s => %s", i_ctx->service_name,
                         ip_str, resolved_ip_str);
                failed = true;
            } else {
                ZITI_LOG(DEBUG, "intercept hostname %s for service[%s] is not an ip", ip_str, i_ctx->service_name);
                if (ipaddr_aton(resolved_ip_str, &cidr->ip) != 0) {
                    ZITI_LOG(ERROR, "failed to parse '%s' as ip address (provided by dns manager)", resolved_ip_str);
                    failed = true;
                }
            }
        }
    }

    if (!failed) {
        STAILQ_INSERT_TAIL(&i_ctx->cidrs, cidr, entries);
    } else {
        free(cidr);
    }

    if (ip_str != cidr_str) {
        free((char *)ip_str);
    }
}

void intercept_ctx_add_port_range(intercept_ctx_t *i_ctx, uint16_t low, uint16_t high) {
    port_range_t *pr = calloc(1, sizeof(port_range_t));
    pr->low = low;
    pr->high = high;
    STAILQ_INSERT_TAIL(&i_ctx->port_ranges, pr, entries);
}

/** intercept a service as described by the intercept_ctx */
int ziti_tunneler_intercept(tunneler_context tnlr_ctx, intercept_ctx_t *i_ctx) {
    if (tnlr_ctx == NULL) {
        ZITI_LOG(ERROR, "null tnlr_ctx");
        return -1;
    }
    struct intercept_s *new, *last;

    for (last = tnlr_ctx->intercepts; last != NULL; last = last->next) {
        if (last->next == NULL) break;
    }

    new = calloc(1, sizeof(struct intercept_s));
    new->ctx = i_ctx;
    new->next = NULL;

    if (last == NULL) {
        tnlr_ctx->intercepts = new;
    } else {
        last->next = new;
    }

    return 0;
}

void ziti_tunneler_stop_intercepting(tunneler_context tnlr_ctx, void *ziti_ctx, const char *service_name) {
    ZITI_LOG(DEBUG, "removing intercept for service %s", service_name);
    struct intercept_s *intercept, *prev = NULL;

    if (tnlr_ctx == NULL) {
        ZITI_LOG(DEBUG, "null tnlr_ctx");
        return;
    }

    for (intercept = tnlr_ctx->intercepts; intercept != NULL; intercept = intercept->next) {
        if (strcmp(intercept->ctx->service_name, service_name) == 0 &&
            intercept->ctx->ziti_ctx == ziti_ctx) {
            if (prev != NULL) {
                prev->next = intercept->next;
            } else {
                tnlr_ctx->intercepts = intercept->next;
            }
            // todo free intercept_ctx
        }
        prev = intercept;
    }
}

/** called by tunneler application when data is read from a ziti connection */
ssize_t ziti_tunneler_write(tunneler_io_context *tnlr_io_ctx, const void *data, size_t len) {
    if (tnlr_io_ctx == NULL || *tnlr_io_ctx == NULL) {
        ZITI_LOG(WARN, "null tunneler io context");
        return -1;
    }

    ssize_t r;
    switch ((*tnlr_io_ctx)->proto) {
        case tun_tcp:
            r = tunneler_tcp_write((*tnlr_io_ctx)->tcp, data, len);
            break;
        case tun_udp:
            r = tunneler_udp_write((*tnlr_io_ctx)->udp.pcb, data, len);
            break;
    }

    if (r < 0) {
        ZITI_LOG(ERROR, "failed to write to client");
        ziti_tunneler_close(tnlr_io_ctx);
        return -1;
    }
    struct tcp_pcb *pcb = (*tnlr_io_ctx)->tcp;

    return r;
}

/** called by tunneler application when a ziti connection closes */
int ziti_tunneler_close(tunneler_io_context *tnlr_io_ctx) {
    if (tnlr_io_ctx == NULL || *tnlr_io_ctx == NULL) {
        ZITI_LOG(INFO, "null tnlr_io_ctx");
        return 0;
    }
    ZITI_LOG(INFO, "closing connection: service=%s, client=%s",
            (*tnlr_io_ctx)->service_name, (*tnlr_io_ctx)->client);
    switch ((*tnlr_io_ctx)->proto) {
        case tun_tcp:
            tunneler_tcp_close((*tnlr_io_ctx)->tcp);
            (*tnlr_io_ctx)->tcp = NULL;
            break;
        case tun_udp:
            tunneler_udp_close((*tnlr_io_ctx)->udp.pcb);
            (*tnlr_io_ctx)->udp.pcb = NULL;
            break;
        default:
            ZITI_LOG(ERROR, "unknown proto %d", (*tnlr_io_ctx)->proto);
            break;
    }

    free(*tnlr_io_ctx);
    *tnlr_io_ctx = NULL;
    return 0;
}

/** called by tunneler application when an EOF is received from */
int ziti_tunneler_close_write(tunneler_io_context *tnlr_io_ctx) {
    if (tnlr_io_ctx == NULL || *tnlr_io_ctx == NULL) {
        ZITI_LOG(INFO, "null tnlr_io_ctx");
        return 0;
    }
    ZITI_LOG(INFO, "closing write connection: service=%s, client=%s",
            (*tnlr_io_ctx)->service_name, (*tnlr_io_ctx)->client);
    switch ((*tnlr_io_ctx)->proto) {
        case tun_tcp:
            tunneler_tcp_close_write((*tnlr_io_ctx)->tcp);
            break;
        default:
            ZITI_LOG(WARN, "not sending FIN on %d connection", (*tnlr_io_ctx)->proto);
            break;
    }
    return 0;
}

static void on_tun_data(uv_poll_t * req, int status, int events) {
    if (status != 0) {
        ZITI_LOG(WARN, "not sure why status is %d", status);
        return;
    }

    if (events & UV_READABLE) {
        netif_shim_input(netif_default);
    }
}

static void check_lwip_timeouts(uv_timer_t * handle) {
    sys_check_timeouts();
}

/**
 * set up a protocol handler. lwip will call recv_fn with arg for each
 * packet that matches the protocol.
 */
static struct raw_pcb * init_protocol_handler(u8_t proto, raw_recv_fn recv_fn, void *arg) {
    struct raw_pcb *pcb;
    err_t err;

    if ((pcb = raw_new_ip_type(IPADDR_TYPE_ANY, proto)) == NULL) {
        ZITI_LOG(ERROR, "failed to allocate raw pcb for protocol %d", proto);
        return NULL;
    }

    if ((err = raw_bind(pcb, IP_ANY_TYPE)) != ERR_OK) {
        ZITI_LOG(ERROR, "failed to bind for protocol %d: error %d", proto, err);
        raw_remove(pcb);
        return NULL;
    }

    raw_bind_netif(pcb, netif_default);
    raw_recv(pcb, recv_fn, arg);

    return pcb;
}

static void run_packet_loop(uv_loop_t *loop, tunneler_context tnlr_ctx) {
    if (tnlr_ctx->opts.ziti_close == NULL || tnlr_ctx->opts.ziti_dial == NULL ||
        tnlr_ctx->opts.ziti_write == NULL || tnlr_ctx->opts.ziti_host_v1 == NULL) {
        ZITI_LOG(ERROR, "ziti_sdk_* callback options cannot be null");
        exit(1);
    }

    lwip_init();

    netif_driver netif_driver = tnlr_ctx->opts.netif_driver;
    if (netif_add_noaddr(&tnlr_ctx->netif, netif_driver, netif_shim_init, ip_input) == NULL) {
        ZITI_LOG(ERROR, "netif_add failed");
        exit(1);
    }

    netif_set_default(&tnlr_ctx->netif);
    netif_set_link_up(&tnlr_ctx->netif);
    netif_set_up(&tnlr_ctx->netif);

    if (netif_driver->setup) {
        netif_driver->setup(netif_driver->handle, loop, on_packet, netif_default);
    } else if (netif_driver->uv_poll_init) {
        netif_driver->uv_poll_init(netif_driver->handle, loop, &tnlr_ctx->netif_poll_req);
        if (uv_poll_start(&tnlr_ctx->netif_poll_req, UV_READABLE, on_tun_data) != 0) {
            ZITI_LOG(ERROR, "failed to start tun poll handle");
            exit(1);
        }
    } else {
        ZITI_LOG(WARN, "no method to initiate tunnel reader, maybe it's ok");
    }

    if ((tnlr_ctx->tcp = init_protocol_handler(IP_PROTO_TCP, recv_tcp, tnlr_ctx)) == NULL) {
        ZITI_LOG(ERROR, "tcp setup failed");
        exit(1);
    }
    if ((tnlr_ctx->udp = init_protocol_handler(IP_PROTO_UDP, recv_udp, tnlr_ctx)) == NULL) {
        ZITI_LOG(ERROR, "udp setup failed");
        exit(1);
    }

    uv_timer_init(loop, &tnlr_ctx->lwip_timer_req);
    uv_timer_start(&tnlr_ctx->lwip_timer_req, check_lwip_timeouts, 0, 10);
}

#define _str(x) #x
#define str(x) _str(x)
const char* ziti_tunneler_version() {
    return str(GIT_VERSION);
}