/*
 Copyright NetFoundry Inc.

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

#include <string.h>

#include "tunnel_udp.h"
#include "ziti_tunnel_priv.h"

#define UDP_TIMEOUT 30000

// initiate orderly shutdown
static void udp_timeout_cb(uv_timer_t *t) {
    struct io_ctx_s *io = t->data;
    tunneler_io_context  tnlr_io = io->tnlr_io;
    if (tnlr_io) {
        TNL_LOG(TRACE, "initiating close idle_timeout[%d] src[%s] dst[%s] service[%s]", tnlr_io->idle_timeout,
                tnlr_io->client, tnlr_io->intercepted, tnlr_io->service_name);
    }
    io->close_fn(io->ziti_io);
}

static void to_ziti(struct io_ctx_s *io, struct pbuf *p) {
    static bool log_stalled_warns = true;
    if (io == NULL) {
        TNL_LOG(ERR, "null io");
        if (p != NULL) {
            pbuf_free(p);
        }
        return;
    }

    if (p == NULL) {
        TNL_LOG(TRACE, "no data to write");
        return;
    }

    struct pbuf *recv_data = p;
    uv_timer_start(io->tnlr_io->conn_timer, udp_timeout_cb, UDP_TIMEOUT, 0);

    do {
        TNL_LOG(TRACE, "writing %d bytes to ziti src[%s] dst[%s] service[%s]", recv_data->len,
                io->tnlr_io->client, io->tnlr_io->intercepted, io->tnlr_io->service_name);
        struct write_ctx_s *wr_ctx = calloc(1, sizeof(struct write_ctx_s));
        wr_ctx->pbuf = recv_data;
        wr_ctx->udp = io->tnlr_io->udp;
        wr_ctx->ack = tunneler_udp_ack;
        struct pbuf *next = recv_data->next;
        // break the chain to prevent pbuf_free from iterating and freeing subsequent pbufs
        recv_data->next = NULL;
        recv_data = next;

        ssize_t s = io->write_fn(io->ziti_io, wr_ctx, wr_ctx->pbuf->payload, wr_ctx->pbuf->len);
        if (s == ERR_WOULDBLOCK) {
            tunneler_udp_ack(wr_ctx);
            free(wr_ctx);
            if (log_stalled_warns) {
                TNL_LOG(WARN, "ziti_write stalled: dropping UDP packets until buffers are released service=%s, client=%s, ret=%ld",
                        io->tnlr_io->service_name, io->tnlr_io->client, s);
            }
            break;
        } else if (s < 0) {
            tunneler_udp_ack(wr_ctx);
            free(wr_ctx);
            TNL_LOG(ERR, "ziti_write failed: service=%s, client=%s, ret=%ld", io->tnlr_io->service_name, io->tnlr_io->client, s);
            io->close_fn(io->ziti_io);
            break;
        } else if (s == 0 && !log_stalled_warns) {
            TNL_LOG(INFO, "ziti_write un-stalled: service=%s client=%s", io->tnlr_io->service_name, io->tnlr_io->client);
            log_stalled_warns = true;
        }
    } while (recv_data != NULL);
}

/** called by lwip when a packet arrives from a connected client and the ziti service is connected */
void on_udp_client_data(void *io_context, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port) {
    if (io_context == NULL) {
        TNL_LOG(INFO, "conn was closed");
        return;
    }
    TNL_LOG(VERBOSE, "%d bytes from %s:%d", p->len, ipaddr_ntoa(addr), port);

    struct io_ctx_s *io = io_context;
    if (!io->tnlr_io->conn_timer) {
        io->tnlr_io->conn_timer = calloc(1, sizeof(uv_timer_t));
        io->tnlr_io->conn_timer->data = io;
        uv_timer_init(io->tnlr_io->tnlr_ctx->loop, io->tnlr_io->conn_timer);
    }

    to_ziti(io_context, p);
}

void tunneler_udp_ack(struct write_ctx_s *write_ctx) {
    pbuf_free(write_ctx->pbuf);
}

int tunneler_udp_close(struct udp_pcb *pcb) {
    struct io_ctx_s *io_ctx = pcb->recv_arg;
    tunneler_io_context tnlr_io_ctx = io_ctx->tnlr_io;
    TNL_LOG(DEBUG, "closing src[%s] dst[%s] service[%s]",
            tnlr_io_ctx->client, tnlr_io_ctx->intercepted, tnlr_io_ctx->service_name);
    udp_remove(pcb);
    return 0;
}

void tunneler_udp_dial_completed(struct io_ctx_s *io, bool ok) {
    if (!ok) {
        ziti_tunneler_close(io->tnlr_io);
    }
}

/** called by lwip when a udp datagram arrives. return 1 to indicate that the IP packet was consumed. */
u8_t recv_udp(void *tnlr_ctx_arg, struct raw_pcb *pcb, struct pbuf *p, const ip_addr_t *addr) {
    tunneler_context tnlr_ctx = tnlr_ctx_arg;

    u16_t iphdr_hlen;
    ip_addr_t src, dst;
    memset(&src, 0, sizeof(src));
    memset(&dst, 0, sizeof(dst));
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
            TNL_LOG(INFO, "unsupported IP protocol version: %d", ip_version);
            return 0;
    }

    /* reach into the pbuf to get to the UDP header */
    struct udp_hdr *udphdr = (struct udp_hdr *)((char*)p->payload + iphdr_hlen);
    u16_t src_p = lwip_ntohs(udphdr->src);
    u16_t dst_p = lwip_ntohs(udphdr->dest);
    char src_str[IPADDR_STRLEN_MAX];
    char dst_str[IPADDR_STRLEN_MAX];
    ipaddr_ntoa_r(&src, src_str, sizeof(src_str));
    ipaddr_ntoa_r(&dst, dst_str, sizeof(dst_str));
    TNL_LOG(TRACE, "received datagram src[%s:%d] dst[%s:%d]", src_str, src_p, dst_str, dst_p);

    /* first see if this datagram belongs to an active connection */
    for (struct udp_pcb *con_pcb = udp_pcbs, *prev = NULL; con_pcb != NULL; con_pcb = con_pcb->next) {
        if (con_pcb->remote_port == src_p &&
            con_pcb->local_port == dst_p &&
            ip_addr_cmp(&con_pcb->remote_ip, &src) &&
            ip_addr_cmp(&con_pcb->local_ip, &dst)) {
            if (prev != NULL) {
                /* move the pcb to the front of udp_pcbs so that is found faster next time */
                prev->next = con_pcb->next;
                con_pcb->next = udp_pcbs;
                udp_pcbs = con_pcb;
            } else {
                UDP_STATS_INC(udp.cachehit);
            }
            return 0; // let lwip process the datagram
        }
        prev = con_pcb;
    }

    /* is the dest address being intercepted? */
    intercept_ctx_t * intercept_ctx = lookup_intercept_by_address(tnlr_ctx, "udp", &src, &dst, dst_p);
    if (intercept_ctx == NULL) {
        TNL_LOG(TRACE, "no intercepted addresses match udp:%s:%d", dst_str, dst_p);
        return 0;
    }

    ziti_sdk_dial_cb zdial = intercept_ctx->dial_fn ? intercept_ctx->dial_fn : tnlr_ctx->opts.ziti_dial;

    /* make a new pcb for this connection and register it with lwip */
    struct udp_pcb *npcb = udp_new();
    if (npcb == NULL) {
        TNL_LOG(ERR, "unable to allocate UDP pcb - UDP connection limit is %d", MEMP_NUM_UDP_PCB);
        pbuf_free(p);
        return 1;
    }
    ip_addr_set_ipaddr(&npcb->local_ip, &dst);
    npcb->local_port = dst_p;
    err_t err = udp_connect(npcb, &src, src_p);
    if (err != ERR_OK) {
        TNL_LOG(ERR, "failed to udp_connect %s:%d: err: %d", src_str, src_p, err);
        udp_remove(npcb);
        pbuf_free(p);
        return 1;
    }

    udp_bind_netif(npcb, &tnlr_ctx->netif);

    struct io_ctx_s *io = calloc(1, sizeof(struct io_ctx_s));
    if (io == NULL) {
        TNL_LOG(ERR, "failed to allocate io_context");
        udp_remove(npcb);
        pbuf_free(p);
        return 1;
    }
    io->tnlr_io = (tunneler_io_context)calloc(1, sizeof(struct tunneler_io_ctx_s));
    if (io->tnlr_io == NULL) {
        TNL_LOG(ERR, "failed to allocate tunneler io context");
        udp_remove(npcb);
        pbuf_free(p);
        return 1;
    }
    io->tnlr_io->tnlr_ctx = tnlr_ctx;
    io->tnlr_io->proto = tun_udp;
    io->tnlr_io->service_name = strdup(intercept_ctx->service_name);
    snprintf(io->tnlr_io->client, sizeof(io->tnlr_io->client), "udp:%s:%d", src_str, src_p);
    snprintf(io->tnlr_io->intercepted, sizeof(io->tnlr_io->intercepted), "udp:%s:%d", dst_str, dst_p);
    io->tnlr_io->udp = npcb;
    io->ziti_ctx = intercept_ctx->app_intercept_ctx;
    io->write_fn = intercept_ctx->write_fn ? intercept_ctx->write_fn : tnlr_ctx->opts.ziti_write;
    io->close_fn = intercept_ctx->close_fn ? intercept_ctx->close_fn : tnlr_ctx->opts.ziti_close;
    io->tnlr_io->idle_timeout = UDP_TIMEOUT;

    TNL_LOG(DEBUG, "intercepted address[%s] client[%s] service[%s]", io->tnlr_io->intercepted, io->tnlr_io->client,
            intercept_ctx->service_name);

    udp_recv(npcb, on_udp_client_data, io);

    void *ziti_io_ctx = zdial(intercept_ctx->app_intercept_ctx, io);
    if (ziti_io_ctx == NULL) {
        TNL_LOG(ERR, "ziti_dial(%s) failed", intercept_ctx->service_name);
        udp_remove(npcb);
        pbuf_free(p);
        free_tunneler_io_context(&io->tnlr_io);
        free(io);
        return 1;
    }

    return 0; /* lwip will call on_udp_client_data_enqueue for this packet */
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
    struct io_ctx_s *io = pcb->recv_arg;
    if (io->tnlr_io->idle_timeout > 0) {
        uv_timer_start(io->tnlr_io->conn_timer, udp_timeout_cb, io->tnlr_io->idle_timeout, 0);
    }
    return len;
}

struct io_ctx_list_s *tunneler_udp_active(const void *zi_ctx) {
    struct io_ctx_list_s *l = calloc(1, sizeof(struct io_ctx_list_s));
    SLIST_INIT(l);

    for (struct udp_pcb *pcb = udp_pcbs; pcb != NULL; pcb = pcb->next) {
        if (pcb->recv == on_udp_client_data) { // recv_arg contains io_context after dial completes.
            struct io_ctx_s *io = pcb->recv_arg;
            if (io != NULL) {
                tunneler_io_context tnlr_io = io->tnlr_io;
                if (tnlr_io != NULL) {
                    if (io->ziti_ctx == zi_ctx) {
                        struct io_ctx_list_entry_s *n = calloc(1, sizeof(struct io_ctx_list_entry_s));
                        n->io = io;
                        SLIST_INSERT_HEAD(l, n, entries);
                    }
                }
            }
        }
    }

    return l;
}

void tunneler_udp_get_conn(tunnel_ip_conn *conn, struct udp_pcb *pcb) {
    if (!conn || !pcb) return;
    conn->protocol = strdup("udp");
    conn->local_ip = strdup(ipaddr_ntoa(&pcb->local_ip));
    conn->local_port = pcb->local_port;
    conn->remote_ip = strdup(ipaddr_ntoa(&pcb->remote_ip));
    conn->remote_port = pcb->remote_port;
    conn->state = strdup("");
    const char *service = "unknown";
    struct io_ctx_s *io = pcb->recv_arg;
    if (io && io->tnlr_io && io->tnlr_io->service_name) {
        service = io->tnlr_io->service_name;
    }
    conn->service = strdup(service);
}
