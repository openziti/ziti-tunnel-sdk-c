
#include <assert.h>

#include "tunneler_udp.h"
#include "ziti_tunneler_priv.h"
#include "nf/ziti_log.h"

void on_udp_packet(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port) {
    tunneler_io_context ctx = arg;
    ctx->udp.cb(ctx, ctx->udp.ctx, (addr_t)addr, port, p->payload, p->len);
    pbuf_free(p);
}

/** called by lwip when a udp datagram arrives. return 1 to indicate that the IP packet was consumed. */
u8_t recv_udp(void *tnlr_ctx_arg, struct raw_pcb *pcb, struct pbuf *p, const ip_addr_t *addr) {
    tunneler_context tnlr_ctx = tnlr_ctx_arg;
    return 0;
}

int NF_udp_handler(tunneler_context tnlr_ctx, const char *hostname, int port, ziti_udp_cb cb, void *data) {
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

int NF_udp_send(tunneler_io_context tio, addr_t dest, u16_t dport, const void* data, ssize_t len) {
    assert(tio->proto == tun_udp);
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, len, PBUF_RAM);
    memcpy(p->payload, data, len);
    err_t rc = udp_sendto_if_src(tio->udp.pcb, p, dest, dport, netif_default, &tio->udp.pcb->local_ip);
    pbuf_free(p);
    return rc;
}