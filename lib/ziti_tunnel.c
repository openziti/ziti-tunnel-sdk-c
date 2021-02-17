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

struct resolve_req {
    struct pbuf *qp;
    ip_addr_t addr;
    u16_t port;
    tunneler_context tnlr_ctx;
};

static void run_packet_loop(uv_loop_t *loop, tunneler_context tnlr_ctx);

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
    run_packet_loop(loop, ctx);

    return ctx;
}

/** called by tunneler application when data has been successfully written to ziti */
void ziti_tunneler_ack(struct write_ctx_s *write_ctx) {
    write_ctx->ack(write_ctx);
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

int ziti_tunneler_host_v1(tunneler_context tnlr_ctx, const void *ziti_ctx, const char *service_name, const char *protocol, const char *hostname, int port) {
    tnlr_ctx->opts.ziti_host_v1((void *) ziti_ctx, tnlr_ctx->loop, service_name, protocol, hostname, port);
    ZITI_LOG(INFO, "hosting service %s at %s:%s:%d", service_name, protocol, hostname, port);
    return 0;
}

static void send_dns_resp(uint8_t *resp, size_t resp_len, void *ctx) {
    struct resolve_req *rreq = ctx;

    ZITI_LOG(INFO, "sending DNS resp[%zd] -> %s:%d", resp_len, ipaddr_ntoa(&rreq->addr), rreq->port);
    struct pbuf *rp = pbuf_alloc(PBUF_TRANSPORT, resp_len, PBUF_RAM);
    memcpy(rp->payload, resp, resp_len);

    err_t err = udp_sendto_if_src(rreq->tnlr_ctx->dns_pcb, rp, &rreq->addr, rreq->port,
                                  netif_default, &rreq->tnlr_ctx->dns_pcb->local_ip);
    if (err != ERR_OK) {
        ZITI_LOG(WARN, "udp_send() DNS response: %d", err);
    }

    pbuf_free(rp);
    pbuf_free(rreq->qp);
    free(rreq);
}

static void on_dns_packet(void *arg, struct udp_pcb *pcb, struct pbuf *p,
    const ip_addr_t *addr, u16_t port) {
    tunneler_context tnlr_ctx = arg;

    struct resolve_req *rr = calloc(1,sizeof(struct resolve_req));
    rr->qp = p;
    rr->addr = *addr;
    rr->port = port;
    rr->tnlr_ctx = tnlr_ctx;

    int rc = tnlr_ctx->dns->query(tnlr_ctx->dns, p->payload, p->len, send_dns_resp, rr);
    if (rc != 0) {
        ZITI_LOG(WARN, "DNS resolve error: %d", rc);
        pbuf_free(p);
        free(rr);
    }
}

void ziti_tunneler_set_dns(tunneler_context tnlr_ctx, dns_manager *dns) {
    tnlr_ctx->dns = dns;
    if (dns->internal_dns) {
        tnlr_ctx->dns_pcb = udp_new();
        ip_addr_t dns_addr = {
                .type = IPADDR_TYPE_V4,
                .u_addr.ip4.addr = dns->dns_ip,
        };
        udp_bind(tnlr_ctx->dns_pcb, &dns_addr, dns->dns_port);
        udp_recv(tnlr_ctx->dns_pcb, on_dns_packet, tnlr_ctx);
    }
}

/** arrange to intercept traffic defined by a v1 client tunneler config */
int ziti_tunneler_intercept_v1(tunneler_context tnlr_ctx, const void *ziti_ctx, const char *service_id, const char *service_name, const char *hostname, int port) {
    ip_addr_t intercept_ip;
    const char *ip;
    if (ipaddr_aton(hostname, &intercept_ip) == 0) {
        if (tnlr_ctx->dns) {
            ip = assign_ip(hostname);
            if (tnlr_ctx->dns->apply(tnlr_ctx->dns, hostname, ip) != 0) {
                ZITI_LOG(ERROR, "failed to apply DNS mapping for service[%s]: %s => %s", service_id, hostname, ip);
            }
            else {
                ZITI_LOG(INFO, "service[%s]: mapped v1 intercept hostname[%s] => ip[%s]", service_id, hostname, ip);
            }
        } else {
            ZITI_LOG(DEBUG, "v1 intercept hostname %s for service id %s is not an ip", hostname, service_id);
            return -1;
        }
    } else {
        ip = hostname;
    }

    add_v1_intercept(tnlr_ctx, ziti_ctx, service_id, service_name, ip, port);
    ZITI_LOG(INFO, "intercepting service %s at %s:%d (svcid %s)", service_name, hostname, port, service_id);
    return 0;
}

static void tunneler_kill_active(const void *ztx, const char *service_name) {
    struct io_ctx_list_s *l;
    ziti_sdk_close_cb zclose;

    l = tunneler_tcp_active(ztx, service_name);
    while (!SLIST_EMPTY(l)) {
        struct io_ctx_list_entry_s *n = SLIST_FIRST(l);
        // close the ziti connection, which also closes the underlay
        zclose = n->io->tnlr_io->tnlr_ctx->opts.ziti_close;
        if (zclose) zclose(n->io->ziti_io);
        SLIST_REMOVE_HEAD(l, entries);
        free(n);
    }
    free(l);

    // todo be selective about protocols when merging newer config types
    l = tunneler_udp_active(ztx, service_name);
    while (!SLIST_EMPTY(l)) {
        struct io_ctx_list_entry_s *n = SLIST_FIRST(l);
        // close the ziti connection, which also closes the underlay
        zclose = n->io->tnlr_io->tnlr_ctx->opts.ziti_close;
        if (zclose) zclose(n->io->ziti_io);
        SLIST_REMOVE_HEAD(l, entries);
        free(n);
    }
    free(l);
}

void ziti_tunneler_stop_intercepting(tunneler_context tnlr_ctx, const char *service_id) {
    ZITI_LOG(DEBUG, "removing intercept for service id %s", service_id);
    struct intercept_s *intercept, *prev = NULL;
    const void *ziti_ctx = NULL;
    const char *service_name = NULL;

    if (tnlr_ctx == NULL) {
        ZITI_LOG(DEBUG, "null tnlr_ctx");
        return;
    }

    // find the service name and ziti_context for this service id
    for (intercept = tnlr_ctx->intercepts; intercept != NULL; intercept = intercept->next) {
        if (strcmp(intercept->ctx.service_id, service_id) == 0) {
            ziti_ctx = intercept->ctx.ziti_ctx;
            service_name = intercept->ctx.service_name;
            break;
        }
    }

    // kill active connections
    if (service_name != NULL && ziti_ctx != NULL) {
        tunneler_kill_active(ziti_ctx, service_name);
    }

    remove_intercept(tnlr_ctx, service_id);
}

/** called by tunneler application when data is read from a ziti connection */
ssize_t ziti_tunneler_write(tunneler_io_context tnlr_io_ctx, const void *data, size_t len) {
    if (tnlr_io_ctx == NULL) {
        ZITI_LOG(WARN, "null tunneler io context");
        return -1;
    }

    ssize_t r;
    switch (tnlr_io_ctx->proto) {
        case tun_tcp:
            r = tunneler_tcp_write(tnlr_io_ctx->tcp, data, len);
            break;
        case tun_udp:
            r = tunneler_udp_write(tnlr_io_ctx->udp.pcb, data, len);
            break;
    }

    return r;
}

/** called by tunneler application when a ziti connection closes */
int ziti_tunneler_close(tunneler_io_context tnlr_io_ctx) {
    if (tnlr_io_ctx == NULL) {
        ZITI_LOG(INFO, "null tnlr_io_ctx");
        return 0;
    }
    ZITI_LOG(INFO, "closing connection: service=%s, client=%s",
            tnlr_io_ctx->service_name, tnlr_io_ctx->client);
    switch (tnlr_io_ctx->proto) {
        case tun_tcp:
            tunneler_tcp_close(tnlr_io_ctx->tcp);
            tnlr_io_ctx->tcp = NULL;
            break;
        case tun_udp:
            tunneler_udp_close(tnlr_io_ctx->udp.pcb);
            tnlr_io_ctx->udp.pcb = NULL;
            break;
        default:
            ZITI_LOG(ERROR, "unknown proto %d", tnlr_io_ctx->proto);
            break;
    }

    free(tnlr_io_ctx);
    return 0;
}

/** called by tunneler application when an EOF is received from ziti */
int ziti_tunneler_close_write(tunneler_io_context tnlr_io_ctx) {
    if (tnlr_io_ctx == NULL) {
        ZITI_LOG(INFO, "null tnlr_io_ctx");
        return 0;
    }
    ZITI_LOG(INFO, "closing write connection: service=%s, client=%s",
            tnlr_io_ctx->service_name, tnlr_io_ctx->client);
    switch (tnlr_io_ctx->proto) {
        case tun_tcp:
            tunneler_tcp_close_write(tnlr_io_ctx->tcp);
            break;
        default:
            ZITI_LOG(DEBUG, "not sending FIN on %d connection", tnlr_io_ctx->proto);
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
        tnlr_ctx->opts.ziti_write == NULL || tnlr_ctx->opts.ziti_host_v1 == NULL ||
        tnlr_ctx->opts.ziti_close_write == NULL) {
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