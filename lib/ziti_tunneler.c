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
#include "lwip/ip_addr.h"
#include "lwip/tcp.h"
#include "lwip/timeouts.h"
#include "netif_shim.h"
#include "nf/ziti_tunneler.h"
#include "uv.h"
#include <nf/ziti_log.h>
#include <lwip/udp.h>
#include <assert.h>

// TODO this should be defined in liblwipcore.a (ip.o), but link fails unless we define it here (or link in lwip's ip.o)
struct ip_globals ip_data;

#if 0
struct intercept_v1_s {
    char *  hostname;
    int     port;
};

struct intercept_s {
    uint8_t v;
    char *  service_name;
    union {
        struct intercept_v1_s;
    } intercept;
};
#endif

typedef enum  {
    tun_tcp,
    tun_udp
} tunneler_proto_type;

struct tunneler_ctx_s {
    tunneler_sdk_options opts;
    struct netif netif;
    uv_poll_t    netif_poll_req;
    uv_timer_t   lwip_timer_req;
    struct intercept_s **intercepts;
};

/** context passed to on_accept when a connection is intercepted */
typedef struct intercept_ctx_s {
    tunneler_context  tnlr_ctx;
    const char *      service_name;
    const void *      ziti_ctx;
} *intercept_context;

struct tunneler_io_ctx_s {
    tunneler_context   tnlr_ctx;
    tunneler_proto_type proto;
    union {
        struct tcp_pcb *tcp;
        struct {
            struct udp_pcb *pcb;
            ziti_udp_cb cb;
            void *ctx;
        } udp;
    };
};

struct io_ctx_s {
    tunneler_io_context  tnlr_io_ctx;
    void *               ziti_io_ctx; // context specific to ziti SDK being used by the app.
};

static void run_packet_loop(uv_loop_t *loop, tunneler_context tnlr_ctx);

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
    run_packet_loop(loop, ctx);

    return ctx;
}

struct write_ctx_s {
    struct pbuf * pbuf;
    struct tcp_pcb *pcb;
};

static void free_tunneler_io_context(tunneler_io_context *tnlr_io_ctx) {
    if (tnlr_io_ctx == NULL) {
        return;
    }

    if (*tnlr_io_ctx != NULL) {
        free(*tnlr_io_ctx);
        *tnlr_io_ctx = NULL;
    }
}

/**
 * called by lwip when a client writes to an intercepted connection.
 * pbuf will be null if client has closed the connection.
 */
static err_t on_client_data(void *io_ctx, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
    if (io_ctx == NULL) {
        ZITI_LOG(INFO, "conn was closed err=%d", err);
        return ERR_OK;
    }
    ZITI_LOG(DEBUG, "on_client_data status %d", err);
    struct io_ctx_s *_io_ctx = (struct io_ctx_s *)io_ctx;
    if (err == ERR_OK && p == NULL) {
        tcp_close(pcb);
        _io_ctx->tnlr_io_ctx->tnlr_ctx->opts.ziti_close(_io_ctx->ziti_io_ctx);
        _io_ctx->ziti_io_ctx = NULL;
        free_tunneler_io_context(&(_io_ctx->tnlr_io_ctx));
        free(_io_ctx);
        return err;
    }

    ziti_write_cb zwrite = _io_ctx->tnlr_io_ctx->tnlr_ctx->opts.ziti_write;
    u16_t len = p->len;
    struct write_ctx_s *wr_ctx = calloc(1, sizeof(struct write_ctx_s));
    wr_ctx->pbuf = p;
    wr_ctx->pcb = pcb;
    ziti_conn_state s = zwrite(_io_ctx->ziti_io_ctx, wr_ctx, p->payload, len);
    switch (s) {
        case ZITI_CONNECTED:
            return ERR_OK;
        case ZITI_CONNECTING:
            free(wr_ctx);
            return ERR_CONN;
        case ZITI_FAILED:
        default:
            free(wr_ctx);
            free(_io_ctx);
            pbuf_free(p);
            return ERR_ABRT;
    }
}

/** called by tunneler application when data has been successfully written to ziti */
int NF_tunneler_ack(void *write_ctx) {
    struct write_ctx_s * ctx = write_ctx;
    tcp_recved(ctx->pcb, ctx->pbuf->len);
    pbuf_free(ctx->pbuf);
    free(ctx);
    return 0;
}

void  on_client_err(void *io_ctx, err_t err) {
    // we initiated close and cleared arg err should be ERR_ABRT
    if (io_ctx == NULL) {
        ZITI_LOG(TRACE, "client finished err=%d", err);
    }
    else {
        // TODO handle better?
        ZITI_LOG(ERROR, "unhandled client err=%d", err);
    }
}

/** called by lwip when client sends a TCP ack */
static err_t on_client_ack(void *io_ctx, struct tcp_pcb *pcb, u16_t len) {
    ZITI_LOG(VERBOSE, "on_client_ack %d bytes", len);
    return ERR_OK;
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

/** TODO: call this when we deal with services going away */
static void free_intercept_ctx(intercept_context *ctx) {
    if (ctx == NULL) {
        return;
    }

    if (*ctx != NULL) {
        if ((*ctx)->service_name != NULL) free((char *)(*ctx)->service_name);
        free(*ctx);
        *ctx = NULL;
    }
}

/** called by lwip when a connection is intercepted */
static err_t on_accept(void *intercept_ctx, struct tcp_pcb *pcb, err_t err) {
    intercept_context intercept = (intercept_context)intercept_ctx;
    ZITI_LOG(INFO, "on_accept(%s, %p)", intercept->service_name, pcb);

    if (err != ERR_OK) {
        ZITI_LOG(ERROR, "on_accept error %d", err);
        free_intercept_ctx(&intercept);
        return err;
    }

    ziti_dial_cb zdial = intercept->tnlr_ctx->opts.ziti_dial;
    // set up lwip to call on_client_data with this client's pcb and ziti_io_ctx;
    tunneler_io_context tnlr_io_ctx = new_tunneler_io_context(intercept->tnlr_ctx, pcb);
    void *ziti_io_ctx = zdial(intercept->service_name, intercept->ziti_ctx, tnlr_io_ctx);
    if (ziti_io_ctx == NULL) {
        ZITI_LOG(ERROR, "ziti_dial(%s) failed", intercept->service_name);
        free_intercept_ctx(&intercept);
        return ERR_CONN;
    }

    struct io_ctx_s *io_ctx = malloc(sizeof(struct io_ctx_s));
    io_ctx->tnlr_io_ctx = tnlr_io_ctx;
    io_ctx->ziti_io_ctx = ziti_io_ctx;

    tcp_arg(pcb, io_ctx);
    tcp_recv(pcb, on_client_data);
    tcp_sent(pcb, on_client_ack);
    tcp_err(pcb, on_client_err);

    return ERR_OK;
}

/** arrange to intercept traffic defined by a v1 client tunneler config */
int NF_tunneler_intercept_v1(tunneler_context tnlr_ctx, const void *ziti_ctx, const char *service_name, const char *hostname, int port) {
    struct tcp_pcb *pcb;
    if ((pcb = tcp_new()) == NULL) {
        ZITI_LOG(ERROR, "failed to allocate pcb for %s", service_name);
        return -1;
    }

    // TODO: handle hostnames
    ip_addr_t a;
    if (ipaddr_aton(hostname, &a) == 0) {
        ZITI_LOG(ERROR, "invalid intercept ip %s", hostname);
        tcp_close(pcb);
        return -1;
    }

#if 1
    /* TODO: using the lwip raw api for expediency.
     * Eventually we will want to inspect headers (via lwip hooks) and create listener PCBs
     * for matching SYN segments as packets arrive, then pass to tcp_listen_input()
     */
    err_t err;
    if ((err = tcp_bind(pcb, &a, port)) != ERR_OK) {
        ZITI_LOG(ERROR, "failed to bind address: error %d", err);
        tcp_close(pcb);
        return -1;
    }

    if ((pcb = tcp_listen_with_backlog(pcb, TCP_DEFAULT_LISTEN_BACKLOG)) == NULL) {
        ZITI_LOG(ERROR, "tcp_listen failed");
        return -1;
    }
    tcp_bind_netif(pcb, netif_default);
#endif

    // pass enough context to on_accept (via the pcb) so ziti SDK can be used to dial/read/write the service
    intercept_context intercept_ctx = new_intercept_ctx(tnlr_ctx, service_name, ziti_ctx);
    if (intercept_ctx == NULL) {
        ZITI_LOG(ERROR, "failed to allocate intercept context for %s", service_name);
        tcp_close(pcb);
        return -1;
    }

    tcp_arg(pcb, intercept_ctx);
    tcp_accept(pcb, on_accept);

    return 0;
}

/** called by tunneler application when data is read from a ziti connection */
int NF_tunneler_write(tunneler_io_context *tnlr_io_ctx, const void *data, size_t len) {
    if (tnlr_io_ctx == NULL || *tnlr_io_ctx == NULL) {
        ZITI_LOG(WARN, "null tunneler io context");
        return -1;
    }

    assert((*tnlr_io_ctx)->proto == tun_tcp);
    struct tcp_pcb *pcb = (*tnlr_io_ctx)->tcp;
    if (pcb == NULL) {
        ZITI_LOG(WARN, "null pcb");
        NF_tunneler_close(tnlr_io_ctx);
        return -1;
    }

    int qlen = tcp_sndqueuelen(pcb);
    if (qlen > TCP_SND_QUEUELEN) {
        ZITI_LOG(INFO, "we are in for it now sndqueuelen %d, %d", qlen, TCP_SND_QUEUELEN);
    }
    // avoid ERR_MEM.
    int sendlen = min(len, tcp_sndbuf(pcb));

    err_t w_err = tcp_write(pcb, data, (u16_t)sendlen, TCP_WRITE_FLAG_COPY); // TODO hold data until client acks... via on_client_ack maybe? then we wouldn't need to copy here.
    if (w_err != ERR_OK) {
        ZITI_LOG(ERROR, "failed to tcp_write %d (%d, %zd)", w_err, sendlen, len);
        NF_tunneler_close(tnlr_io_ctx);
        return -1;
    }

    if (tcp_output(pcb) != ERR_OK) {
        ZITI_LOG(ERROR, "failed to tcp_output");
        return -1;
    }

    return sendlen;
}

/** called by tunneler application when a ziti connection closes */
int NF_tunneler_close(tunneler_io_context *tnlr_io_ctx) {
    if (tnlr_io_ctx != NULL && *tnlr_io_ctx != NULL) {
        if ((*tnlr_io_ctx)->tcp != NULL) {
            tcp_arg((*tnlr_io_ctx)->tcp, NULL);
            tcp_recv((*tnlr_io_ctx)->tcp, NULL);
            if (tcp_close((*tnlr_io_ctx)->tcp) != ERR_OK) {
                ZITI_LOG(ERROR, "failed to tcp_close");
                return -1;
            }
            (*tnlr_io_ctx)->tcp = NULL;
        }
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