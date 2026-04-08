// Copyright 2026 NetFoundry Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


#include "tunnel_l2.h"
#include "netif_shim.h"
#include "ziti_tunnel_priv.h"
#include "lwip/prot/ethernet.h"

#include <string.h>

static model_map l2_conns = {};

void tunneler_l2_add_conn(uint16_t ethtype, const io_ctx_t *io) {
    model_map_setl(&l2_conns, ethtype, io);
    TNL_LOG(INFO, "ethtype 0x%04x --> %p, s=%s", ethtype, io, io->tnlr_io->service_name);
}

void tunneler_l2_del_conn(uint16_t ethtype) {
    model_map_removel(&l2_conns, ethtype);
}

io_ctx_t *tunneler_l2_get_conn(uint16_t ethtype) {
    io_ctx_t *io = model_map_getl(&l2_conns, ethtype);
    TNL_LOG(VERBOSE, "ethtype %04x --> %p", ethtype, io);
    return io;
}

void tunneler_l2_dial_completed(struct io_ctx_s *io, bool ok) {
    if (!ok) {
        model_map_remove(&l2_conns, io->tnlr_io->intercepted);
        ziti_tunneler_close(io->tnlr_io);
    }
}

void tunneler_l2_ack(struct write_ctx_s *write_ctx) {
}

ssize_t tunneler_l2_write(struct netif *netif, const void *data, size_t len) {
    static bool log_pbuf_errors = true;
    struct pbuf *p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
    if (p != NULL) {
        if (!log_pbuf_errors) {
            TNL_LOG(INFO, "pbufs are now available. packets will no longer be dropped");
            log_pbuf_errors = true;
        }
        err_t e = pbuf_take(p, data, len);
        if (e != ERR_OK) {
            TNL_LOG(ERR, "pbuf_take failed: %d", e);
            pbuf_free(p);
            return -1;
        }
        /* Rewrite the Ethernet source MAC to this interface's own hardware
         * address.  Hypervisor virtual switches (e.g. Parallels, VMware) may
         * enforce that the source MAC of every transmitted frame matches the
         * MAC registered for the sending VM's NIC and silently drop frames
         * with a foreign source MAC.  The original source MAC in the frame
         * belongs to the intercepting client, which is unknown to the hosting
         * VM's virtual switch, so those frames are dropped after
         * pcap_sendpacket (visible in tcpdump but never transmitted).
         * Rewriting to the hosting interface's own MAC satisfies the filter. */
        if (netif->hwaddr_len >= 6 && len >= 14 && p->len >= 12) {
            struct eth_hdr *eth = (struct eth_hdr *)p->payload;
            memcpy(eth->src.addr, netif->hwaddr, 6);
        }
    } else {
        /* drop packet(); */
        if (log_pbuf_errors) {
            TNL_LOG(ERR, "pbuf_alloc failed. dropping packets until pbufs become available");
            log_pbuf_errors = false;
        }
        return -1;
    }

    err_t e = netif->linkoutput(netif, p);
    pbuf_free(p);
    return (ssize_t) (e == ERR_OK ? len : -1);
}

int tunneler_l2_close(const char *ethtype) {
    uint16_t et = strtol(ethtype, NULL, 16);
    model_map_removel(&l2_conns, et);
    return -1;
}

u8_t recv_l2(struct netif *netif, struct pbuf *p) {
    netif_driver dev = netif->state;
    tunneler_context tnlr = dev->tnlr;
    struct eth_hdr *h = p->payload;
    uint16_t ethtype = htons(h->type);
    io_ctx_t *io = tunneler_l2_get_conn(ethtype);

    if (io == NULL) {
        const intercept_ctx_t *i = lookup_intercept_by_ethtype(tnlr, ethtype);
        if (i == NULL) {
            return 0;
        }

        struct tunneler_io_ctx_s *tnlr_io = calloc(1, sizeof(struct tunneler_io_ctx_s));
        if (tnlr_io == NULL) {
            TNL_LOG(ERR, "failed to allocate tunneler_io_ctx");
            return 0;
        }

        tnlr_io->tnlr_ctx = tnlr;
        tnlr_io->service_name = strdup(i->service_name);
        snprintf(tnlr_io->client, sizeof(tnlr_io->client), "%02x:%02x:%02x:%02x:%02x:%02x",
            h->src.addr[0], h->src.addr[1], h->src.addr[2], h->src.addr[3], h->src.addr[4], h->src.addr[5]);
        snprintf(tnlr_io->intercepted, sizeof(tnlr_io->intercepted), "0x%04x", ethtype);
        tnlr_io->proto = tun_l2;

        io = calloc(1, sizeof(struct io_ctx_s));
        if (io == NULL) {
            TNL_LOG(ERR, "failed to allocate io_context");
            free(tnlr_io);
            return 0;
        }
        io->tnlr_io = tnlr_io;
        io->ziti_ctx = i->app_intercept_ctx;
        io->write_fn = i->write_fn ? i->write_fn : tnlr->opts.ziti_write;
        io->close_write_fn = i->close_write_fn ? i->close_write_fn : tnlr->opts.ziti_close_write;
        io->close_fn = i->close_fn ? i->close_fn : tnlr->opts.ziti_close;

        TNL_LOG(DEBUG, "intercepted address[%s] client[%s] service[%s]", io->tnlr_io->intercepted, io->tnlr_io->client,
                i->service_name);

        ziti_sdk_dial_cb zdial = i->dial_fn ? i->dial_fn : tnlr->opts.ziti_dial;
        const void *ziti_io_ctx = zdial(i->app_intercept_ctx, io); // todo should have one ziti conn per dial identity
        if (ziti_io_ctx == NULL) {
            TNL_LOG(ERR, "ziti_dial(%s) failed", i->service_name);
            ziti_tunneler_close(io->tnlr_io);
            free(io);
            return 0;;
        }

        // add this "connection" to the table. it isn't completed yet but the sdk will queue data until the connection is established.
        tunneler_l2_add_conn(ethtype, io);
    }
    // send (queue) the frame
    ziti_tunnel_pbuf_to_ziti(io, p);
    return 1;
}
