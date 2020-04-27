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

#include "lwip/init.h"
#include "lwip/raw.h"
#include "lwip/timeouts.h"
#include "netif_shim.h"
#include "nf/ziti_tunneler.h"
#include "ziti_tunneler_priv.h"
#include "intercept.h"
#include "tunneler_tcp.h"
#include "uv.h"
#include <nf/ziti_log.h>
#include <lwip/udp.h>
#include <assert.h>

#ifndef _WIN32
#include <sys/param.h>
#define min(x,y) MIN((x),(y))
#endif

// TODO this should be defined in liblwipcore.a (ip.o), but link fails unless we define it here (or link in lwip's ip.o)
struct ip_globals ip_data;

static void run_packet_loop(uv_loop_t *loop, tunneler_context tnlr_ctx);

tunneler_context NF_tunneler_init(tunneler_sdk_options *opts, uv_loop_t *loop) {
    if (opts == NULL) {
        ZITI_LOG(ERROR, "invalid tunneler options");
        return NULL;
    }

    struct tunneler_ctx_s *ctx = calloc(1, sizeof(struct tunneler_ctx_s));
    if (ctx == NULL) {
        ZITI_LOG(ERROR, "failed to allocate tunneler context");
        return NULL;
    }
    memcpy(&ctx->opts, opts, sizeof(ctx->opts));
    run_packet_loop(loop, ctx);

    return ctx;
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

/** called by tunneler application when data has been successfully written to ziti */
void NF_tunneler_ack(void *write_ctx) {
    struct write_ctx_s * ctx = write_ctx;
    tunneler_tcp_ack(ctx->pcb, ctx->pbuf);
    free(ctx);
}

static tunneler_io_context new_tunneler_io_context(tunneler_context tnlr_ctx, struct tcp_pcb *pcb) {
    struct tunneler_io_ctx_s *ctx = malloc(sizeof(struct tunneler_io_ctx_s));
    if (ctx == NULL) {
        ZITI_LOG(ERROR, "failed to allocate tunneler_io_ctx");
        return NULL;
    }
    ctx->tnlr_ctx = tnlr_ctx;
    ctx->proto = tun_tcp;
    ctx->tcp = pcb;
    return ctx;
}

/**
 * called by tunneler application when a service dial has completed
 * - let the client know that we have a connection (e.g. send SYN/ACK)
 */
void NF_tunneler_dial_completed(tunneler_io_context *tnlr_io_ctx, void *ziti_io_ctx) {
    struct io_ctx_s *io_ctx = malloc(sizeof(struct io_ctx_s));
    io_ctx->tnlr_io_ctx = *tnlr_io_ctx;
    io_ctx->ziti_io_ctx = ziti_io_ctx;

    switch ((*tnlr_io_ctx)->proto) {
        case tun_tcp:
            tunneler_tcp_dial_completed((*tnlr_io_ctx)->tcp, io_ctx);
            break;
        case tun_udp:
            // TODO
            break;
        default:
            // TODO
            break;
    }
}

/** arrange to intercept traffic defined by a v1 client tunneler config */
int NF_tunneler_intercept_v1(tunneler_context tnlr_ctx, const void *ziti_ctx, const char *service_name, const char *hostname, int port) {
    ip_addr_t intercept_ip;

    if (ipaddr_aton(hostname, &intercept_ip) == 0) {
        ZITI_LOG(DEBUG, "v1 intercept hostname %s for service %s is not an ip", hostname, service_name);
        /* TODO: handle hostnames */
        return -1;
    }

    add_v1_intercept(tnlr_ctx, ziti_ctx, service_name, hostname, port);

    return 0;
}

/** called by tunneler application when data is read from a ziti connection */
int NF_tunneler_write(tunneler_io_context *tnlr_io_ctx, const void *data, size_t len) {
    if (tnlr_io_ctx == NULL || *tnlr_io_ctx == NULL) {
        ZITI_LOG(WARN, "null tunneler io context");
        return -1;
    }

    int r;
    switch ((*tnlr_io_ctx)->proto) {
        case tun_tcp:
            r = tunneler_tcp_write((*tnlr_io_ctx)->tcp, data, len);
            break;
        case tun_udp:
            ZITI_LOG(ERROR, "no udp yet"); // TODO handle UDP write
            r = -1;
            break;
    }

    if (r < 0) {
        ZITI_LOG(ERROR, "failed to write to client");
        NF_tunneler_close(tnlr_io_ctx);
        return -1;
    }
    struct tcp_pcb *pcb = (*tnlr_io_ctx)->tcp;

    return r;
}

/** called by tunneler application when a ziti connection closes */
int NF_tunneler_close(tunneler_io_context *tnlr_io_ctx) {
    if (tnlr_io_ctx != NULL && *tnlr_io_ctx != NULL) {
        tunneler_tcp_close((*tnlr_io_ctx)->tcp);
        free(*tnlr_io_ctx);
        *tnlr_io_ctx = NULL;
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
static struct raw_pcb *setup_handler(u8_t proto, raw_recv_fn recv_fn, void *arg) {
    err_t err;
    struct raw_pcb *pcb;

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

/* TODO this is a hack to test packet filtering. do this for real soon */
static uint8_t active_phony = 0;
uint8_t is_active(const char *session_key) {
    if (active_phony == 0) {
        active_phony = 1;
        return 0;
    }
    return 1;
}

/** called by lwip when a udp datagram arrives. return 1 to indicate that the IP packet was consumed. */
static u8_t recv_udp(void *tnlr_ctx_arg, struct raw_pcb *pcb, struct pbuf *p, const ip_addr_t *addr) {
    tunneler_context tnlr_ctx = tnlr_ctx_arg;
    return 0;
}

static void run_packet_loop(uv_loop_t *loop, tunneler_context tnlr_ctx) {
    if (tnlr_ctx->opts.ziti_close == NULL || tnlr_ctx->opts.ziti_dial == NULL || tnlr_ctx->opts.ziti_write == NULL) {
        ZITI_LOG(ERROR, "ziti_* callback options cannot be null");
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

    if ((tnlr_ctx->tcp = setup_handler(IP_PROTO_TCP, recv_tcp, tnlr_ctx)) == NULL) {
        ZITI_LOG(ERROR, "tcp setup failed");
        exit(1);
    }
    if ((tnlr_ctx->udp = setup_handler(IP_PROTO_UDP, recv_udp, tnlr_ctx)) == NULL) {
        ZITI_LOG(ERROR, "udp setup failed");
        exit(1);
    }

    uv_timer_init(loop, &tnlr_ctx->lwip_timer_req);
    uv_timer_start(&tnlr_ctx->lwip_timer_req, check_lwip_timeouts, 0, 100);
}

static void on_udp_packet(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port) {
    tunneler_io_context ctx = arg;
    ctx->udp.cb(ctx, ctx->udp.ctx, (addr_t)addr, port, p->payload, p->len);
    pbuf_free(p);
}

extern int NF_udp_handler(tunneler_context tnlr_ctx, const char *hostname, int port, ziti_udp_cb cb, void *data) {
    struct udp_pcb *pcb;

    if ((pcb = udp_new()) == NULL) {
        ZITI_LOG(ERROR, "failed to allocate pcb for %s", hostname);
        return -1;
    }

    ip_addr_t a;
    if (ipaddr_aton(hostname, &a) == 0) {
        ZITI_LOG(ERROR, "invalid intercept ip %s", hostname);
        free(pcb);
        return -1;
    }

    err_t err;
    if ((err = udp_bind(pcb, &a, port)) != ERR_OK) {
        ZITI_LOG(ERROR, "failed to bind address: error %d", err);
        free(pcb);
        return -1;
    }

    udp_bind_netif(pcb, netif_default);
    tunneler_io_context ctx = (tunneler_io_context)calloc(1, sizeof(struct tunneler_io_ctx_s));
    ctx->tnlr_ctx = tnlr_ctx;
    ctx->proto = tun_udp;
    ctx->udp.pcb = pcb;
    ctx->udp.cb = cb;
    ctx->udp.ctx = data;
    udp_recv(pcb, on_udp_packet, ctx);

    return 0;
}

extern int NF_udp_send(tunneler_io_context tio, addr_t dest, u16_t dport, const void* data, ssize_t len) {
    assert(tio->proto == tun_udp);
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, len, PBUF_RAM);
    memcpy(p->payload, data, len);
    err_t rc = udp_sendto_if_src(tio->udp.pcb, p, dest, dport, netif_default, &tio->udp.pcb->local_ip);
    pbuf_free(p);
    return rc;
}