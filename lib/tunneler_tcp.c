#include <stdlib.h>
#include "tunneler_tcp.h"
//#include "lwip_cloned_fns.h"
#include "ziti_tunneler_priv.h"
#include "intercept.h"
#include "ziti/ziti_log.h"

#if _WIN32
#define MIN(a,b) ((a)<(b) ? (a) : (b))
#endif

/** called by lwip when a client sends a SYN segment to an intercepted address.
 * this only exists to appease lwip */
static err_t on_accept(void *arg, struct tcp_pcb *pcb, err_t err) {
    ZITI_LOG(DEBUG, "on_accept: %d", err);
    return ERR_OK;
}

/** create a tcp connection to be managed by lwip */
static struct tcp_pcb *new_tcp_pcb(ip_addr_t src, ip_addr_t dest, struct tcp_hdr *tcphdr) {
    /** associate all injected PCBs with the same phony listener to appease some LWIP checks */
    static struct tcp_pcb_listen * phony_listener = NULL;
    if (phony_listener == NULL) {
        if ((phony_listener = memp_malloc(MEMP_TCP_PCB_LISTEN)) == NULL) {
            ZITI_LOG(ERROR, "failed to allocate listener");
            return NULL;
        }
        phony_listener->accept = on_accept;
    }
    struct tcp_pcb *npcb = tcp_new();
    if (npcb == NULL) {
        ZITI_LOG(ERROR, "tcp_new failed");
        return NULL;
    }
    /* Set up the new PCB. */
    ip_addr_copy(npcb->local_ip, dest);
    ip_addr_copy(npcb->remote_ip, src);
    npcb->local_port = lwip_ntohs(tcphdr->dest);
    npcb->remote_port = lwip_ntohs(tcphdr->src);
    npcb->state = SYN_RCVD;
    npcb->rcv_nxt = lwip_ntohl(tcphdr->seqno) + 1;
    npcb->rcv_ann_right_edge = npcb->rcv_nxt;
    u32_t iss = tcp_next_iss(npcb);
    npcb->snd_wl2 = iss;
    npcb->snd_nxt = iss;
    npcb->lastack = iss;
    npcb->snd_lbb = iss;
    npcb->snd_wl1 = lwip_ntohl(tcphdr->seqno) - 1;/* initialise to seqno-1 to force window update */
    /* allocate a listener and set accept fn to appease lwip */
    npcb->listener = phony_listener;
    npcb->netif_idx = netif_get_index(netif_default);

    /* Register the new PCB so that we can begin receiving segments for it. */
    TCP_REG_ACTIVE(npcb);

    /* Parse any options in the SYN. */
    //tunneler_tcp_parseopt(npcb);
    npcb->snd_wnd = lwip_ntohs(tcphdr->wnd);
    npcb->snd_wnd_max = npcb->snd_wnd;

#if TCP_CALCULATE_EFF_SEND_MSS
    npcb->mss = tcp_eff_send_mss(npcb->mss, &npcb->local_ip, &npcb->remote_ip);
#endif /* TCP_CALCULATE_EFF_SEND_MSS */

    MIB2_STATS_INC(mib2.tcppassiveopens);

#if LWIP_TCP_PCB_NUM_EXT_ARGS
    if (tcp_ext_arg_invoke_callbacks_passive_open(pcb, npcb) != ERR_OK) {
      tcp_abandon(npcb, 0);
      return NULL;
    }
#endif
    return npcb;
}

/**
 * called by lwip when a client writes to an intercepted connection.
 * pbuf will be null if client has closed the connection.
 */
static err_t on_tcp_client_data(void *io_ctx, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
    if (io_ctx == NULL) {
        ZITI_LOG(INFO, "conn was closed err=%d", err);
        return ERR_OK;
    }
    ZITI_LOG(DEBUG, "on_tcp_client_data status %d", err);
    struct io_ctx_s *_io_ctx = (struct io_ctx_s *)io_ctx;
    tunneler_io_context tnlr_io_ctx = *_io_ctx->tnlr_io_ctx_p;

    if (err == ERR_OK && p == NULL) {
        tcp_close(pcb);
        tnlr_io_ctx->tnlr_ctx->opts.ziti_close(_io_ctx->ziti_io_ctx);
        _io_ctx->ziti_io_ctx = NULL;
        free_tunneler_io_context(_io_ctx->tnlr_io_ctx_p);
        free(_io_ctx);
        return err;
    }

    ziti_sdk_write_cb zwrite = tnlr_io_ctx->tnlr_ctx->opts.ziti_write;
    u16_t len = p->len;
    struct write_ctx_s *wr_ctx = calloc(1, sizeof(struct write_ctx_s));
    wr_ctx->pbuf = p;
    wr_ctx->tcp = pcb;
    wr_ctx->ack = tunneler_tcp_ack;
    ssize_t s = zwrite(_io_ctx->ziti_io_ctx, wr_ctx, p->payload, len);
    if (s < 0) {
        free(wr_ctx);
        free(_io_ctx);
        pbuf_free(p);
        return ERR_ABRT;
    }
    return ERR_OK;
}

static void  on_tcp_client_err(void *io_ctx, err_t err) {
    // we initiated close and cleared arg err should be ERR_ABRT
    if (io_ctx == NULL) {
        ZITI_LOG(TRACE, "client finished err=%d", err);
    }
    else {
        // TODO handle better?
        ZITI_LOG(ERROR, "unhandled client err=%d", err);
    }
}

ssize_t tunneler_tcp_write(struct tcp_pcb *pcb, const void *data, size_t len) {
    if (pcb == NULL) {
        ZITI_LOG(WARN, "null pcb");
        return -1;
    }

    int qlen = tcp_sndqueuelen(pcb);
    if (qlen > TCP_SND_QUEUELEN) {
        ZITI_LOG(INFO, "we are in for it now sndqueuelen %d, %d", qlen, TCP_SND_QUEUELEN);
    }
    // avoid ERR_MEM.
    size_t sendlen = MIN(len, tcp_sndbuf(pcb));

    err_t w_err = tcp_write(pcb, data, (u16_t)sendlen, TCP_WRITE_FLAG_COPY); // TODO hold data until client acks... via on_client_ack maybe? then we wouldn't need to copy here.
    if (w_err != ERR_OK) {
        ZITI_LOG(ERROR, "failed to tcp_write %d (%ld, %zd)", w_err, sendlen, len);
        return -1;
    }

    if (tcp_output(pcb) != ERR_OK) {
        ZITI_LOG(ERROR, "failed to tcp_output");
        return -1;
    }

    return sendlen;
}

void tunneler_tcp_ack(struct write_ctx_s *write_ctx) {
    struct write_ctx_s *wr_ctx = write_ctx;
    tcp_recved(wr_ctx->tcp, wr_ctx->pbuf->len);
    pbuf_free(wr_ctx->pbuf);
}

int tunneler_tcp_close(struct tcp_pcb *pcb) {
    if (pcb != NULL) {
        tcp_arg(pcb, NULL);
        tcp_recv(pcb, NULL);
        if (tcp_close(pcb) != ERR_OK) {
            ZITI_LOG(ERROR, "failed to tcp_close");
            return -1;
        }
    }
    return 0;
}

void tunneler_tcp_dial_completed(tunneler_io_context *tnlr_io_ctx, void *ziti_io_ctx, bool ok) {
    struct io_ctx_s *io_ctx = malloc(sizeof(struct io_ctx_s));
    io_ctx->tnlr_io_ctx_p = tnlr_io_ctx;
    io_ctx->ziti_io_ctx = ziti_io_ctx;
    struct tcp_pcb *pcb = (*tnlr_io_ctx)->tcp;

    tcp_arg(pcb, io_ctx);
    tcp_recv(pcb, on_tcp_client_data);
    tcp_err(pcb, on_tcp_client_err);

    /* Send a SYN|ACK together with the MSS option. */
    err_t rc = tcp_enqueue_flags(pcb, TCP_SYN | TCP_ACK);
    if (rc != ERR_OK) {
        tcp_abandon(pcb, 0);
        return;
    }

    tcp_output((*tnlr_io_ctx)->tcp);
    memp_free(MEMP_TCP_PCB_LISTEN, pcb->listener);
}

static tunneler_io_context new_tunneler_io_context(tunneler_context tnlr_ctx, const char *service_name, struct tcp_pcb *pcb) {
    struct tunneler_io_ctx_s *ctx = malloc(sizeof(struct tunneler_io_ctx_s));
    if (ctx == NULL) {
        ZITI_LOG(ERROR, "failed to allocate tunneler_io_ctx");
        return NULL;
    }
    ctx->tnlr_ctx = tnlr_ctx;
    ctx->service_name = service_name;
    ctx->proto = tun_tcp;
    ctx->tcp = pcb;
    return ctx;
}

/** called by lwip when a tcp segment arrives. return 1 to indicate that the IP packet was consumed. */
u8_t recv_tcp(void *tnlr_ctx_arg, struct raw_pcb *pcb, struct pbuf *p, const ip_addr_t *addr) {
    tunneler_context tnlr_ctx = tnlr_ctx_arg;

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

    /* reach into the pbuf to get to the TCP header */
    struct tcp_hdr *tcphdr = (struct tcp_hdr *)(p->payload + iphdr_hlen);
    u16_t src_p = lwip_ntohs(tcphdr->src);
    u16_t dst_p = lwip_ntohs(tcphdr->dest);

    ZITI_LOG(DEBUG, "received segment %s:%d->%s:%d",
             ipaddr_ntoa(&src), src_p, ipaddr_ntoa(&dst), dst_p);

    u8_t flags = TCPH_FLAGS(tcphdr);
    if (!(flags & TCP_SYN)) {
        /* this isn't a SYN segment, so let lwip process it */
        return 0;
    }

    intercept_ctx_t *intercept_ctx = lookup_l4_intercept(tnlr_ctx, &dst, dst_p);
    if (intercept_ctx == NULL) {
        /* dst address is not being intercepted. don't consume */
        ZITI_LOG(DEBUG, "no v1 intercepts match %s:%d", ipaddr_ntoa(&dst), dst_p);
        return 0;
    }

    /* we know this is a SYN segment for an intercepted address, and we will process it */
    ZITI_LOG(INFO, "intercepting packet with dst %s:%d for service %s", ipaddr_ntoa(&dst), dst_p, intercept_ctx->service_name);
    ziti_sdk_dial_cb zdial = tnlr_ctx->opts.ziti_dial;

    struct tcp_pcb *npcb = new_tcp_pcb(src, dst, tcphdr);
    tunneler_io_context tnlr_io_ctx = new_tunneler_io_context(tnlr_ctx, intercept_ctx->service_name, npcb);
    ZITI_LOG(INFO, "created tnlr_io_ctx %p", tnlr_io_ctx);
    void *ziti_io_ctx = zdial(intercept_ctx, tnlr_io_ctx);
    if (ziti_io_ctx == NULL) {
        ZITI_LOG(ERROR, "ziti_dial(%s) failed", intercept_ctx->service_name);
        free_tunneler_io_context(&tnlr_io_ctx);
        err_t rc = tcp_enqueue_flags(npcb, TCP_FIN);
        if (rc != ERR_OK) {
            tcp_abandon(npcb, 0);
            return 0;
        }
        tcp_output(npcb);
    }
    /* now we wait for the tunneler app to call ziti_tunneler_dial_complete() */

    //pbuf_free(p);
    return 0; // TODO we should return 1, but that seems to cause the client to stall irrecoverably.
}