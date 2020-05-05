#include "tunneler_udp.h"
#include "ziti_tunneler_priv.h"
#include "intercept.h"
#include "nf/ziti_log.h"

static void to_ziti(tunneler_io_context tnlr_io_ctx, void *ziti_io_ctx, struct pbuf *p) {
    struct pbuf *recv_data = NULL;
    if (tnlr_io_ctx->udp.queued != NULL) {
        if (p != NULL) {
            pbuf_cat(tnlr_io_ctx->udp.queued, p);
        }
        recv_data = tnlr_io_ctx->udp.queued;
        tnlr_io_ctx->udp.queued = NULL;
    } else {
        recv_data = p;
    }

    if (recv_data == NULL) {
        ZITI_LOG(DEBUG, "no data to write");
        return;
    }

    do {
        ZITI_LOG(INFO, "writing %d bytes to ziti", recv_data->len);
        ziti_write_cb zwrite = tnlr_io_ctx->tnlr_ctx->opts.ziti_write;
        struct write_ctx_s *wr_ctx = calloc(1, sizeof(struct write_ctx_s));
        wr_ctx->pbuf = recv_data;
        wr_ctx->udp = tnlr_io_ctx->udp.pcb;
        wr_ctx->ack = tunneler_udp_ack;
        ssize_t s = zwrite(ziti_io_ctx, wr_ctx, recv_data->payload, recv_data->len);
        if (s < 0) {
            free(wr_ctx);
            pbuf_free(recv_data);
        }
        recv_data = recv_data->next;
    } while (recv_data != NULL);
}

/** called by lwip when a packet arrives from a connected client */
void on_udp_client_data(void *io_context, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port) {
    if (io_context == NULL) {
        ZITI_LOG(INFO, "conn was closed");
        return;
    }
    ZITI_LOG(DEBUG, "on_udp_client_data %d bytes from %s:%d", p->len, ipaddr_ntoa(addr), port);

    struct io_ctx_s *io_ctx = (struct io_ctx_s *) io_context;
    switch (io_ctx->tnlr_io_ctx->udp.dial_status) {
        case initiated:
            ZITI_LOG(INFO, "dial_status is initiated");
            if (io_ctx->tnlr_io_ctx->udp.queued == NULL) {
                io_ctx->tnlr_io_ctx->udp.queued = p;
            } else {
                pbuf_cat(io_ctx->tnlr_io_ctx->udp.queued, p);
            }
            ZITI_LOG(INFO, "queued %d bytes", io_ctx->tnlr_io_ctx->udp.queued->len);
            return;
        case succeeded:
            to_ziti(io_ctx->tnlr_io_ctx, io_ctx->ziti_io_ctx, p);
            break;
        case failed:
        default:
            ZITI_LOG(INFO, "dial_status is failed or invalid");
            NF_tunneler_close(&io_ctx->tnlr_io_ctx);
            return;
    }
}

void tunneler_udp_ack(struct write_ctx_s *write_ctx) {
    pbuf_free(write_ctx->pbuf);
}

int tunneler_udp_close(struct udp_pcb *pcb) {
    if (pcb != NULL) {
        udp_remove(pcb);
    }
    return 0;
}

void tunneler_udp_dial_completed(tunneler_io_context *tnlr_io_ctx, void *ziti_io_ctx, bool ok) {
    (*tnlr_io_ctx)->udp.dial_status = ok ? succeeded : failed;
    /* send any data that was queued while waiting for the dial to complete */
    if (ok) {
        to_ziti(*tnlr_io_ctx, ziti_io_ctx, NULL);
    }

    // no longer need to enqueue datagrams from the client. flush queued packets now, probably?
}

/** called by lwip when a udp datagram arrives. return 1 to indicate that the IP packet was consumed. */
u8_t recv_udp(void *tnlr_ctx_arg, struct raw_pcb *pcb, struct pbuf *p, const ip_addr_t *addr) {
    tunneler_context tnlr_ctx = tnlr_ctx_arg;
    struct udp_pcb *con_pcb, *prev;

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
    for (con_pcb = udp_pcbs, prev = NULL; con_pcb != NULL; con_pcb = con_pcb->next) {
        if (con_pcb->remote_port == src_p && ip_addr_cmp(&con_pcb->remote_ip, &src)) {
            if (prev != NULL) {
                /* move the pcb to the front of udp_pcbs so that is found faster next time */
                prev->next = con_pcb->next;
                con_pcb->next = udp_pcbs;
                udp_pcbs = con_pcb;
            }
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
    ziti_dial_cb zdial = tnlr_ctx->opts.ziti_dial;

    /* make a new pcb for this connection and register it with lwip */
    struct udp_pcb *npcb = udp_new();
    ip_addr_set_ipaddr(&npcb->local_ip, &dst);
    npcb->local_port = dst_p;
    err_t err = udp_connect(npcb, &src, src_p);
    if (err != ERR_OK) {
        ZITI_LOG(ERROR, "failed to udp_connect %s:%d: err: %d", ipaddr_ntoa(&src), src_p, err);
        udp_remove(npcb);
        pbuf_free(p);
        return 1;
    }

    udp_bind_netif(npcb, &tnlr_ctx->netif);

    tunneler_io_context ctx = (tunneler_io_context)calloc(1, sizeof(struct tunneler_io_ctx_s));
    ctx->tnlr_ctx = tnlr_ctx;
    ctx->proto = tun_udp;
    ctx->service_name = intercept_ctx->service_name;
    ctx->udp.pcb = npcb;
    ctx->udp.dial_status = initiated;
    ctx->udp.queued = NULL;

    void *ziti_io_ctx = zdial(intercept_ctx, ctx);
    if (ziti_io_ctx == NULL) {
        ZITI_LOG(ERROR, "ziti_dial(%s) failed", intercept_ctx->service_name);
        udp_remove(npcb);
        pbuf_free(p);
        free_tunneler_io_context(&ctx);
        return 1;
    }

    struct io_ctx_s *io_ctx = calloc(1, sizeof(struct io_ctx_s));
    io_ctx->tnlr_io_ctx = ctx;
    io_ctx->ziti_io_ctx = ziti_io_ctx;
    udp_recv(npcb, on_udp_client_data, io_ctx);

    return 0; /* lwip will call on_udp_client_data for this packet */
}

ssize_t tunneler_udp_write(struct udp_pcb *pcb, const void *data, size_t len) {
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, len, PBUF_RAM);
    memcpy(p->payload, data, len);
    /* use udp_sendto_if_src even though local and remote addresses are in pcb, because
     * udp_send verifies that the dest IP matches the netif's IP, and fails with ERR_RTE.
     */
    err_t err = udp_sendto_if_src(pcb, p, &pcb->remote_ip, pcb->remote_port, netif_default, &pcb->local_ip);
    pbuf_free(p);
    if (err != ERR_OK) {
        return -1;
    }
    return len;

}