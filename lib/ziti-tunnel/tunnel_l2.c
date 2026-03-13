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

static model_map l2_conns = {};

void tunneler_l2_dial_completed(struct io_ctx_s *io, bool ok) {
    if (!ok) {
        model_map_remove(&l2_conns, io->tnlr_io->intercepted);
        ziti_tunneler_close(io->tnlr_io);
    }
}

void tunneler_l2_ack(struct write_ctx_s *write_ctx) {
    pbuf_free(write_ctx->pbuf);
    free(write_ctx);
}

ssize_t tunneler_l2_write(struct netif *netif, const void *data, size_t len) {
    struct pbuf *p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
    pbuf_take(p, data, len);
    netif->linkoutput(netif, p);
    return -1;
}

int tunneler_l2_close(const char *ethtype) {
    model_map_remove(&l2_conns, ethtype);
    return -1;
}

u8_t recv_l2(struct netif *netif, struct pbuf *p) {
    netif_driver dev = netif->state;
    tunneler_context tnlr = dev->tnlr;
    struct eth_hdr *h = p->payload;
    uint16_t ethtype = htons(h->type);
    // todo look for an active connection to write to

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
    snprintf(tnlr_io->intercepted, sizeof(tnlr_io->intercepted), "%04x", ethtype);
    tnlr_io->proto = tun_l2;

    struct io_ctx_s *io = calloc(1, sizeof(struct io_ctx_s));
    if (io == NULL) {
        TNL_LOG(ERR, "failed to allocate io_context");
        free(tnlr_io);
        goto done;
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
        goto done;
    }

    // add this "connection" to the table. it isn't completed yet but the sdk will queue data until the connection is established.
    model_map_set(&l2_conns, io->tnlr_io->intercepted, io);

    // send (queue) the frame
    ziti_tunnel_pbuf_to_ziti(io, p);

    done:
    return 1;
}
