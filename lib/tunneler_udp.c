
#include <assert.h>

#include "tunneler_udp.h"
#include "ziti_tunneler_priv.h"
#include "intercept.h"
#include "nf/ziti_log.h"

/** called by lwip when a packet arrives from a connected client */
void on_udp_client_data(void *io_ctx, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port) {
    if (io_ctx == NULL) {
        ZITI_LOG(INFO, "conn was closed");
        return;
    }
    ZITI_LOG(DEBUG, "on_udp_client_data %d bytes from %s:%d", p->len, ipaddr_ntoa(addr), port);
    struct io_ctx_s *_io_ctx = (struct io_ctx_s *)io_ctx;
    ziti_write_cb zwrite = _io_ctx->tnlr_io_ctx->tnlr_ctx->opts.ziti_write;

    struct write_ctx_s *wr_ctx = calloc(1, sizeof(struct write_ctx_s));
    // TODO udp types
    wr_ctx->pbuf = p;
    wr_ctx->pcb = pcb;
    ssize_t s = zwrite(_io_ctx->ziti_io_ctx, wr_ctx, p->payload, p->len);
    if (s < 0) {
        free(wr_ctx);
        free(_io_ctx);
        pbuf_free(p);
    }
}

void tunneler_udp_ack(struct udp_pcb *pcb, struct pbuf *p) {
    pbuf_free(p);
}

int tunneler_udp_close(struct udp_pcb *pcb) {
    if (pcb != NULL) {
        udp_remove(pcb);
    }
    return 0;
}

void tunneler_udp_dial_completed(struct udp_pcb *pcb, struct io_ctx_s *io_ctx, bool ok) {
    udp_recv(pcb, on_udp_client_data, io_ctx);
    // TODO connect?
}

/** called by lwip when a udp datagram arrives. return 1 to indicate that the IP packet was consumed. */
u8_t recv_udp(void *tnlr_ctx_arg, struct raw_pcb *pcb, struct pbuf *p, const ip_addr_t *addr) {
    tunneler_context tnlr_ctx = tnlr_ctx_arg;
    struct udp_pcb *con_pcb, uncon_pcb;

    u16_t iphdr_hlen;
    ip_addr_t src, dst;
    char ip_version = IPH_V((struct ip_hdr *)(p->payload));

    /* figure out where the tcp header is in the pbuf. don't modify
     * the pbuf until we know that this segment should be intercepted.
     */
    switch (ip_version) {
        case 4: {
            struct ip_hdr *iphdr = p->payload;
            iphdr_hlen = IPH_HL_BYTES(iphdr);
            ip_addr_copy_from_ip4(src, iphdr->src);
            ip_addr_copy_from_ip4(dst, iphdr->dest);
        }
            break;
        case 6: {
            struct ip6_hdr *iphdr = p->payload;
            iphdr_hlen = IP6_HLEN;
            ip_addr_copy_from_ip6_packed(src, iphdr->src);
            ip_addr_copy_from_ip6_packed(dst, iphdr->dest);
        }
            break;
        default:
            ZITI_LOG(INFO, "unsupported IP protocol version: %d", ip_version);
            return 0;
    }

    /* reach into the pbuf to get to the UDP header */
    struct udp_hdr *udphdr = (struct udp_hdr *)(p->payload + iphdr_hlen);
    u16_t src_p = lwip_ntohs(udphdr->src);
    u16_t dst_p = lwip_ntohs(udphdr->dest);

    /* first see if this datagram belongs to an active connection */
    for (con_pcb = udp_pcbs; con_pcb != NULL; con_pcb = con_pcb->next) {
        if (con_pcb->remote_port == src_p && ip_addr_cmp(&con_pcb->remote_ip, &src)) {
            return 0; // let lwip process the datagram
        }
    }

    /* is the dest address being intercepted? */
    intercept_ctx_t * intercept_ctx = lookup_l4_intercept(tnlr_ctx, &dst, dst_p);
    if (intercept_ctx == NULL) {
        ZITI_LOG(DEBUG, "no v1 intercepts match %s:%d", ipaddr_ntoa(&dst), dst_p);
        return 0;
    }

    ZITI_LOG(INFO, "intercepting packet with dst %s:%d for service %s", ipaddr_ntoa(&dst), dst_p, intercept_ctx->service_name);
    /* make a new pcb for this connection and register it with lwip */
    struct udp_pcb *npcb = udp_new();
    err_t err = udp_bind(npcb, &dst, dst_p);
    if (err != ERR_OK) {
        ZITI_LOG(ERROR, "failed to udp_bind %s:%d: err: %d", ipaddr_ntoa(&dst), dst_p, err);
        udp_remove(npcb);
        return 1;
    }

    udp_bind_netif(npcb, &tnlr_ctx->netif);

    tunneler_io_context ctx = (tunneler_io_context)calloc(1, sizeof(struct tunneler_io_ctx_s));
    ctx->tnlr_ctx = tnlr_ctx;
    ctx->proto = tun_udp;
    ctx->udp.pcb = npcb;
    udp_recv(npcb, on_udp_client_data, ctx);

    return 0;
}

ssize_t tunneler_udp_write(struct udp_pcb *pcb, const void *data, size_t len) {
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, len, PBUF_RAM);
    memcpy(p->payload, data, len);
    err_t err = udp_send(pcb, p);
    pbuf_free(p);
    if (err != ERR_OK) {
        return -1;
    }
    return len;

}