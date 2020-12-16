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
#include "tunnel_tcp.h"
#include "tunnel_udp.h"
#include "uv.h"
#include "ziti/ziti_log.h"

#include <string.h>

static void run_packet_loop(uv_loop_t *loop, tunneler_context tnlr_ctx);

STAILQ_HEAD(tlnr_ctx_list_s, tunneler_ctx_s) tnlr_ctx_list_head = STAILQ_HEAD_INITIALIZER(tnlr_ctx_list_head);

tunneler_context ziti_tunneler_init(tunneler_sdk_options *opts, uv_loop_t *loop) {
    ziti_log_init(loop, ZITI_LOG_DEFAULT_LEVEL, NULL);
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
    STAILQ_INIT(&ctx->intercepts);
    run_packet_loop(loop, ctx);

    return ctx;
}

static void tunneler_kill_active(const void *ztx, const char *service_name);

void ziti_tunneler_shutdown(tunneler_context tnlr_ctx) {
    ZITI_LOG(DEBUG, "tnlr_ctx %p", tnlr_ctx);

    while (!STAILQ_EMPTY(&tnlr_ctx->intercepts)) {
        intercept_ctx_t *i = STAILQ_FIRST(&tnlr_ctx->intercepts);
        tunneler_kill_active(i->ziti_ctx, i->service_name);
        STAILQ_REMOVE_HEAD(&tnlr_ctx->intercepts, entries);
    }
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

void free_tunneler_io_context(tunneler_io_context *tnlr_io_ctx_p) {
    if (tnlr_io_ctx_p == NULL) {
        return;
    }

    if (*tnlr_io_ctx_p != NULL) {
        free(*tnlr_io_ctx_p);
        *tnlr_io_ctx_p = NULL;
    }
}

/**
 * called by tunneler application when a service dial has completed
 * - let the client know that we have a connection (e.g. send SYN/ACK)
 */
void ziti_tunneler_dial_completed(struct io_ctx_s *io, bool ok) {
    if (io == NULL) {
        ZITI_LOG(ERROR, "null io");
        return;
    }
    if (io->ziti_io == NULL || io->tnlr_io == NULL) {
        ZITI_LOG(ERROR, "null ziti_io or tnlr_io");
    }
    const char *status = ok ? "succeeded" : "failed";
    ZITI_LOG(INFO, "ziti dial %s: service=%s, client=%s", status, io->tnlr_io->service_name, io->tnlr_io->client);

    switch (io->tnlr_io->proto) {
        case tun_tcp:
            tunneler_tcp_dial_completed(io, ok);
            break;
        case tun_udp:
            tunneler_udp_dial_completed(io, ok);
            break;
        default:
            ZITI_LOG(ERROR, "unknown proto %d", io->tnlr_io->proto);
            break;
    }
}

int ziti_tunneler_host(tunneler_context tnlr_ctx, const void *ziti_ctx, const char *service_name, cfg_type_e cfg_type, void *config) {
    tnlr_ctx->opts.ziti_host((void *) ziti_ctx, tnlr_ctx->loop, service_name, cfg_type, config);
}

void ziti_tunneler_set_dns(tunneler_context tnlr_ctx, dns_manager *dns) {
    tnlr_ctx->dns = dns;
}

void intercept_ctx_add_protocol(intercept_ctx_t *ctx, const char *protocol) {
    protocol_t *proto = calloc(1, sizeof(protocol_t));
    proto->protocol = strdup(protocol);
    STAILQ_INSERT_TAIL(&ctx->protocols, proto, entries);
}

address_t *parse_address(const char *hn_or_ip_or_cidr, dns_manager *dns) {
    address_t *addr = calloc(1, sizeof(address_t));
    strncpy(addr->str, hn_or_ip_or_cidr, sizeof(addr->str));
    addr->is_hostname = false;
    char *prefix_sep = strchr(addr->str, '/');

    if (prefix_sep != NULL) {
        *prefix_sep = '\0';
        addr->prefix_len = (int)strtol(prefix_sep + 1, NULL, 10);
    }

    if (ipaddr_aton(addr->str, &addr->ip) == 0) {
        // does not parse as IP address; assume hostname and try to get IP from the dns manager
        if (dns) {
            const char *resolved_ip_str = assign_ip(addr->str);
            if (dns->apply(dns, addr->str, resolved_ip_str) != 0) {
                ZITI_LOG(ERROR, "failed to apply DNS mapping %s => %s", addr->str, resolved_ip_str);
                free(addr);
                return NULL;
            } else {
                ZITI_LOG(DEBUG, "intercept hostname %s is not an ip", addr->str);
                if (ipaddr_aton(resolved_ip_str, &addr->ip) != 0) {
                    ZITI_LOG(ERROR, "dns manager provided unparsable ip address '%s'", resolved_ip_str);
                    free(addr);
                    return NULL;
                } else {
                    addr->is_hostname = true;
                }
            }
        }
    }

    if (prefix_sep != NULL) {
        *prefix_sep = '/'; // replace '/' that was nulled for easy parsing
    } else {
        // use full ip
        addr->prefix_len = IP_IS_V4(&addr->ip) ? 32 : 128;
    }

    return addr;
}

address_t *intercept_ctx_add_address(tunneler_context tnlr_ctx, intercept_ctx_t *i_ctx, const char *address) {
    address_t *addr = parse_address(address, tnlr_ctx->dns);

    if (addr == NULL) {
        ZITI_LOG(ERROR, "failed to parse address '%s' service[%s]", address, i_ctx->service_name);
        return NULL;
    }

    STAILQ_INSERT_TAIL(&i_ctx->addresses, addr, entries);
    return addr;
}

port_range_t *parse_port_range(uint16_t low, uint16_t high) {
    port_range_t *pr = calloc(1, sizeof(port_range_t));
    if (low <= high) {
        pr->low = low;
        pr->high = high;
    } else {
        pr->low = high;
        pr->high = low;
    }

    if (low == high) {
        snprintf(pr->str, sizeof(pr->str), "%d", low);
    } else {
        snprintf(pr->str, sizeof(pr->str), "[%d-%d]", low, high);
    }
    return pr;
}

port_range_t *intercept_ctx_add_port_range(intercept_ctx_t *i_ctx, uint16_t low, uint16_t high) {
    port_range_t *pr = parse_port_range(low, high);
    STAILQ_INSERT_TAIL(&i_ctx->port_ranges, pr, entries);
    return pr;
}

/** intercept a service as described by the intercept_ctx */
int ziti_tunneler_intercept(tunneler_context tnlr_ctx, intercept_ctx_t *i_ctx) {
    if (tnlr_ctx == NULL) {
        ZITI_LOG(ERROR, "null tnlr_ctx");
        return -1;
    }

    address_t *address;
    STAILQ_FOREACH(address, &i_ctx->addresses, entries) {
        protocol_t *proto;
        STAILQ_FOREACH(proto, &i_ctx->protocols, entries) {
            port_range_t *pr;
            STAILQ_FOREACH(pr, &i_ctx->port_ranges, entries) {
                // todo find conflicts with services
                // intercept_ctx_t *match;
                // match = lookup_intercept_by_address(tnlr_ctx, proto->protocol, &address->ip, pr->low, pr->high);
                ZITI_LOG(INFO, "intercepting %s:%s:%s service[%s]",
                         proto->protocol, address->str, pr->str, i_ctx->service_name);
            }
        }
    }

    STAILQ_FOREACH(address, &i_ctx->addresses, entries) {
         add_route(tnlr_ctx->opts.netif_driver, address);
    }

    STAILQ_INSERT_TAIL(&tnlr_ctx->intercepts, (struct intercept_ctx_s *)i_ctx, entries);

    return 0;
}

static void tunneler_kill_active(const void *ztx, const char *service_name) {
    struct io_ctx_list_s *l;

    l = tunneler_tcp_active(ztx, service_name);
    while (!SLIST_EMPTY(l)) {
        struct io_ctx_list_entry_s *n = SLIST_FIRST(l);
        ZITI_LOG(INFO, "service[%s] client[%s] killing active connection", service_name, n->io->tnlr_io->client);
        ziti_tunneler_close(&n->io->tnlr_io);
        SLIST_REMOVE_HEAD(l, entries);
        free(n);
    }

    // todo be selective about protocols when merging newer config types
    l = tunneler_udp_active(ztx, service_name);
    while (!SLIST_EMPTY(l)) {
        struct io_ctx_list_entry_s *n = SLIST_FIRST(l);
        ZITI_LOG(INFO, "service[%s] client[%s] killing active connection", service_name, n->io->tnlr_io->client);
        ziti_tunneler_close(&n->io->tnlr_io);
        SLIST_REMOVE_HEAD(l, entries);
        free(n);
    }
}

// when called due to service unavailable we want to remove from tnlr_ctx.
// when called due to conflict we want to mark as disabled
void ziti_tunneler_stop_intercepting(tunneler_context tnlr_ctx, void *ziti_ctx, const char *service_name) {
    ZITI_LOG(DEBUG, "removing intercept for service %s", service_name);
    struct intercept_ctx_s *intercept;

    if (tnlr_ctx == NULL) {
        ZITI_LOG(DEBUG, "null tnlr_ctx");
        return;
    }

    tunneler_kill_active(ziti_ctx, service_name);

    STAILQ_FOREACH(intercept, &tnlr_ctx->intercepts, entries) {
        if (strcmp(intercept->service_name, service_name) == 0 &&
            intercept->ziti_ctx == ziti_ctx) {
            STAILQ_REMOVE(&tnlr_ctx->intercepts, intercept, intercept_ctx_s, entries);
            // todo deep free intercept_ctx
            free(intercept);
            break;
        }
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
int ziti_tunneler_close(tunneler_io_context *tnlr_io_ctx_p) {
    if (tnlr_io_ctx_p == NULL || *tnlr_io_ctx_p == NULL) {
        ZITI_LOG(INFO, "null tnlr_io_ctx");
        return 0;
    }
    ZITI_LOG(INFO, "closing connection: service=%s, client=%s",
             (*tnlr_io_ctx_p)->service_name, (*tnlr_io_ctx_p)->client);
    switch ((*tnlr_io_ctx_p)->proto) {
        case tun_tcp:
            tunneler_tcp_close((*tnlr_io_ctx_p)->tcp);
            (*tnlr_io_ctx_p)->tcp = NULL;
            break;
        case tun_udp:
            tunneler_udp_close((*tnlr_io_ctx_p)->udp.pcb);
            (*tnlr_io_ctx_p)->udp.pcb = NULL;
            break;
        default:
            ZITI_LOG(ERROR, "unknown proto %d", (*tnlr_io_ctx_p)->proto);
            break;
    }

    free(*tnlr_io_ctx_p);
    *tnlr_io_ctx_p = NULL;
    return 0;
}

/** called by tunneler application when an EOF is received from */
int ziti_tunneler_close_write(tunneler_io_context *tnlr_io_ctx_p) {
    if (tnlr_io_ctx_p == NULL || *tnlr_io_ctx_p == NULL) {
        ZITI_LOG(INFO, "null tnlr_io_ctx");
        return 0;
    }
    ZITI_LOG(INFO, "closing write connection: service=%s, client=%s",
             (*tnlr_io_ctx_p)->service_name, (*tnlr_io_ctx_p)->client);
    switch ((*tnlr_io_ctx_p)->proto) {
        case tun_tcp:
            tunneler_tcp_close_write((*tnlr_io_ctx_p)->tcp);
            break;
        default:
            ZITI_LOG(WARN, "not sending FIN on %d connection", (*tnlr_io_ctx_p)->proto);
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
    tunneler_sdk_options opts = tnlr_ctx->opts;
    if (opts.ziti_close == NULL || opts.ziti_dial == NULL || opts.ziti_write == NULL ||
        opts.ziti_host == NULL) {
        ZITI_LOG(ERROR, "ziti_sdk_* callback options cannot be null");
        exit(1);
    }

    lwip_init();

    netif_driver netif_driver = opts.netif_driver;
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