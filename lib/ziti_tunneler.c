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

#include "lwip/init.h"
#include "lwip/tcp.h"
#include "lwip/timeouts.h"
#include "netif_shim.h"
#include "nf/ziti_tunneler.h"
#include "uv.h"
#include "priv/ziti_utils.h"

// TODO this should be defined in liblwipcore.a (ip.o), but link fails unless we define it here (or link in lwip's ip.o)
struct ip_globals ip_data;

struct tunneler_ctx_s {
    tunneler_sdk_options opts;
};

/** context passed to on_accept when a connection is intercepted */
typedef struct intercept_ctx_s {
    tunneler_context  tnlr_ctx;
    const char *      service_name;
    struct sockaddr * addr;
    const void *      ziti_ctx;
} *intercept_context;

struct tunneler_io_ctx_s {
    tunneler_context   tnlr_ctx;
    struct tcp_pcb *   pcb;
};

static void run_packet_loop(uv_loop_t *loop, netif_driver netif);
tunneler_context NF_tunneler_init(tunneler_sdk_options *opts, uv_loop_t *loop) {
    if (opts == NULL) {
        ZITI_LOG(ERROR, "invalid tunneler options");
        return NULL;
    }

    struct tunneler_ctx_s *ctx = malloc(sizeof(struct tunneler_ctx_s));
    if (ctx == NULL) {
        ZITI_LOG(ERROR, "failed to allocate tunneler context");
        return NULL;
    }

    memcpy(&ctx->opts, opts, sizeof(ctx->opts));

    if (opts->netif != NULL) {
        run_packet_loop(loop, opts->netif);
    }

    return ctx;
}

struct io_ctx_s {
    tunneler_context tnlr_ctx;
    void *           ziti_io_ctx;
};

/** called by lwip when a client writes to an intercepted connection */
err_t on_client_data(void *io_ctx, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
    if (p == NULL) {
        return ZITI_FAILED;
    }

    struct io_ctx_s *_io_ctx = (struct io_ctx_s *)io_ctx;
    ziti_write_cb zwrite;
    if ((zwrite = _io_ctx->tnlr_ctx->opts.ziti_write) == NULL) {
        ZITI_LOG(ERROR, "ziti_write_cb is invalid");
        return ERR_ARG;
    }
    ziti_conn_state s = zwrite(_io_ctx->ziti_io_ctx, p->payload, p->len);
    switch (s) {
        case ZITI_CONNECTED:
            tcp_recved(pcb, p->len);
            return ERR_OK;
        case ZITI_CONNECTING:
            return ERR_CONN;
        case ZITI_FAILED:
        default:
            return ERR_ABRT;
    }
}

err_t on_client_ack(void *io_ctx, struct tcp_pcb *pcb, u16_t len) {
    ZITI_LOG(INFO, "on_client_ack %d bytes", len);
    return ERR_OK;
}

static tunneler_io_context new_tunneler_io_context(tunneler_context tnlr_ctx, struct tcp_pcb *pcb) {
    struct tunneler_io_ctx_s *ctx = malloc(sizeof(struct tunneler_io_ctx_s));
    if (ctx == NULL) {
        ZITI_LOG(ERROR, "failed to allocate tunneler_io_ctx");
        return NULL;
    }
    ctx->tnlr_ctx = tnlr_ctx;
    ctx->pcb = pcb;
    return ctx;
}

/** called by lwip when a connection is intercepted */
static err_t on_accept(void *intercept_ctx, struct tcp_pcb *pcb, err_t err) {
    intercept_context intercept = (intercept_context)intercept_ctx;
    ZITI_LOG(INFO, "on_accept(%s)", intercept->service_name);

    ziti_dial_cb zdial;
    if ((zdial = intercept->tnlr_ctx->opts.ziti_dial) == NULL) {
        ZITI_LOG(ERROR, "ziti_dial_cb is invalid");
        return ERR_ARG;
    }

    // set up lwip to call on_client_data with this client's pcb and ziti_io_ctx;
    tunneler_io_context tnlr_io_ctx = new_tunneler_io_context(intercept->tnlr_ctx, pcb);
    void *ziti_io_ctx = zdial(intercept->service_name, intercept->ziti_ctx, tnlr_io_ctx);
    if (ziti_io_ctx == NULL) {
        ZITI_LOG(ERROR, "ziti_dial(%s) failed", intercept->service_name);
        return ERR_CONN;
    }

    struct io_ctx_s *io_ctx = malloc(sizeof(struct io_ctx_s));
    io_ctx->tnlr_ctx = intercept->tnlr_ctx;
    io_ctx->ziti_io_ctx = ziti_io_ctx;

    tcp_arg(pcb, io_ctx);
    tcp_recv(pcb, on_client_data);
    tcp_sent(pcb, on_client_ack);

    return ERR_OK;
}

static intercept_context new_intercept_ctx(tunneler_context tnlr_ctx, const char *service_name, const void *ziti_dial_ctx) {
    struct intercept_ctx_s *ctx = malloc(sizeof(struct intercept_ctx_s));
    if (ctx == NULL) {
        ZITI_LOG(ERROR, "failed to allocate intercept context for %s", service_name);
        return NULL;
    }

    ctx->service_name = strdup(service_name);
    if (ctx->service_name == NULL) {
        ZITI_LOG(ERROR, "failed to allocate intercept context service name %s", service_name);
        free(ctx);
        return NULL;
    }

    ctx->tnlr_ctx = tnlr_ctx;
    ctx->ziti_ctx = ziti_dial_ctx;

    return ctx;
}

static void free_intercept_ctx(intercept_context ctx) {
    if (ctx != NULL) {
        if (ctx->service_name != NULL) free((char *)ctx->service_name);
        free(ctx);
    }
}

static int intercept_ipv4(tunneler_context tnlr_ctx, const void *ziti_ctx, const char *service_name, struct sockaddr_in *addr_in) {
    intercept_context intercept_ctx = new_intercept_ctx(tnlr_ctx, service_name, ziti_ctx);
    if (intercept_ctx == NULL) {
        ZITI_LOG(ERROR, "failed to allocate intercept context for %s", service_name);
        return -1;
    }

    struct tcp_pcb *pcb;
    if ((pcb = tcp_new()) == NULL) {
        ZITI_LOG(ERROR, "failed to allocate pcb for %s", service_name);
        return -1;
    }

    err_t err;
    if ((err = tcp_bind(pcb, IP_ADDR_ANY, addr_in->sin_port)) != ERR_OK) {
        fprintf(stderr, "failed to bind address: error %d\n", err);
        return -1;
    }

    if ((pcb = tcp_listen_with_backlog(pcb, TCP_DEFAULT_LISTEN_BACKLOG)) == NULL) {
        fprintf(stderr, "tcp_listen failed\n");
        return -1;
    }
    tcp_bind_netif(pcb, netif_default); // TODO is this necessary?

    // pass enough context to on_accept (via the pcb) so ziti SDK can be used to dial the service
    tcp_arg(pcb, intercept_ctx);
    tcp_accept(pcb, on_accept);

    return 0;
}

int NF_tunneler_intercept(tunneler_context tnlr_ctx, const void *ziti_ctx, const char *service_name, const struct sockaddr *addr) {
    switch(addr->sa_family) {
        case AF_INET:
            intercept_ipv4(tnlr_ctx, ziti_ctx, service_name, (struct sockaddr_in *)addr);
    }

    return 0;
}

int NF_tunneler_write(tunneler_io_context tnlr_io_ctx, const void *data, int len) {
    struct tcp_pcb *pcb = tnlr_io_ctx->pcb;
    int nw = 0;

    err_t w_err = tcp_write(pcb, data, len, 0);
    if (w_err != ERR_OK) {
        ZITI_LOG(ERROR, "failed to tcp_write %d", w_err);
        tcp_close(pcb);
        return -1;
    }

    if (tcp_output(pcb) != ERR_OK) {
        ZITI_LOG(ERROR, "failed to tcp_output");
        return -1;
    }

    return 0;
}

int NF_tunneler_close(tunneler_io_context tnlr_io_ctx) {
    if (tnlr_io_ctx == NULL) {
        ZITI_LOG(ERROR, "invalid tnlr_io_ctx", NO_SYS);
        return -1;
    }

    if (tcp_close(tnlr_io_ctx->pcb) != ERR_OK) {
        ZITI_LOG(ERROR, "failed to tcp_close");
    }

    return 0;
}

void on_tun_data(uv_poll_t *req, int status, int events) {
    if (status != 0) {
        ZITI_LOG(WARN, "on_tun_data: not sure why status is %d", status);
        return;
    }

    if (events & UV_READABLE) {
        netif_shim_input(netif_default);
    }
}

static void check_lwip_timeouts(uv_timer_t *handle) {
    sys_check_timeouts();
}

static void run_packet_loop(uv_loop_t *loop, netif_driver nic) {
    struct netif *netif = malloc(sizeof(struct netif));
    if (netif == NULL) {
        ZITI_LOG(ERROR, "failed to allocate lwip netif");
        exit(1);
    }

    lwip_init();

    if (netif_add_noaddr(netif, nic, netif_shim_init, ip_input) == NULL) {
        ZITI_LOG(ERROR, "netif_add failed");
        exit(1);
    }

    netif_set_default(netif);
    netif_set_link_up(netif);
    netif_set_up(netif);

    uv_poll_t *tun_poll_req = nic->uv_poll_init(nic->handle, loop);
    if (uv_poll_start(tun_poll_req, UV_READABLE, on_tun_data) != 0) {
        ZITI_LOG(ERROR, "failed to start tun poll handle");
        exit(1);
    }

    uv_timer_t * timer_timeouts_req = malloc(sizeof(uv_timer_t));  // TODO add to tunneler_context
    uv_timer_init(loop, timer_timeouts_req);
    uv_timer_start(timer_timeouts_req, check_lwip_timeouts, 0, 100);
}