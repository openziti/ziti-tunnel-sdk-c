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

/*
 * pcap_common.c - Platform-neutral pcap L2 netif driver implementation.
 *
 * Shared between the Windows (Npcap) and Linux (libpcap) pcap drivers.
 * Contains no OS-specific code; all pcap calls go through the pcap_ops_t
 * vtable supplied by the platform-specific open function.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <uv.h>
#include <ziti/netif_driver.h>
#include <ziti/ziti_log.h>

#include "pcap_common.h"

#define MAX_FRAME_LEN 65536u

/* -------------------------------------------------------------------------
 * Frame delivery: called on the libuv event-loop thread via uv_async_t.
 * Drains the entire frame queue and delivers each frame to lwIP.
 * ---------------------------------------------------------------------- */
static void pcap_deliver_frames(uv_async_t *ar)
{
    netif_handle h = ar->data;

    for (;;) {
        uv_mutex_lock(&h->frame_lock);
        frame_node_t *node = h->frame_head;
        if (node) {
            h->frame_head = node->next;
            if (!h->frame_head) h->frame_tail = NULL;
        }
        uv_mutex_unlock(&h->frame_lock);

        if (!node) break;

        h->on_packet((const char *)node->data, (ssize_t)node->len, h->netif);
        free(node);
    }
}

/* -------------------------------------------------------------------------
 * Reader thread: calls next_packet in a loop and queues captured frames for
 * delivery on the libuv event-loop thread.
 * ---------------------------------------------------------------------- */
static void pcap_reader_thread(void *arg)
{
    netif_handle h = arg;

    ZITI_LOG(DEBUG, "pcap: reader thread started for '%s'", h->name);

    while (!h->stopping) {
        uint32_t caplen = 0;
        const unsigned char *data = NULL;

        int rc = h->ops.next_packet(h->ops.pcap, &caplen, &data);
        if (rc == 0) continue;   /* read timeout -- check stopping flag */
        if (rc < 0) {
            if (!h->stopping) {
                ZITI_LOG(ERROR, "pcap: next_packet error on '%s': %s",
                         h->name, h->ops.get_error(h->ops.pcap));
            }
            break;
        }

        if (caplen == 0 || data == NULL) continue;

        frame_node_t *node = malloc(offsetof(frame_node_t, data) + caplen);
        if (!node) {
            ZITI_LOG(ERROR, "pcap: OOM dropping frame of %u bytes on '%s'",
                     caplen, h->name);
            continue;
        }
        node->len  = caplen;
        node->next = NULL;
        memcpy(node->data, data, caplen);

        uv_mutex_lock(&h->frame_lock);
        if (h->frame_tail) {
            h->frame_tail->next = node;
        } else {
            h->frame_head = node;
        }
        h->frame_tail = node;
        uv_mutex_unlock(&h->frame_lock);

        uv_async_send(h->read_available);
    }

    ZITI_LOG(DEBUG, "pcap: reader thread exiting for '%s'", h->name);
}

/* -------------------------------------------------------------------------
 * setup_read: spawn the reader thread and wire the uv_async handle.
 * Implements the setup_packet_cb callback in netif_driver_t.
 * ---------------------------------------------------------------------- */
static int pcap_setup_read(netif_handle h, uv_loop_t *loop,
                            packet_cb on_packet, void *netif)
{
    h->on_packet = on_packet;
    h->netif     = netif;

    h->read_available = calloc(1, sizeof(uv_async_t));
    if (!h->read_available) return -1;

    uv_async_init(loop, h->read_available, pcap_deliver_frames);
    h->read_available->data = h;

    uv_thread_create(&h->reader, pcap_reader_thread, h);
    return 0;
}

/* -------------------------------------------------------------------------
 * Write: inject an outbound frame via the platform send_packet operation.
 * ---------------------------------------------------------------------- */
static ssize_t pcap_write(netif_handle h, const void *buf, size_t len)
{
    if (h->ops.send_packet(h->ops.pcap, (const unsigned char *)buf, (int)len) != 0) {
        ZITI_LOG(ERROR, "pcap: send_packet failed on '%s': %s",
                 h->name, h->ops.get_error(h->ops.pcap));
        return -1;
    }
    return (ssize_t)len;
}

/* -------------------------------------------------------------------------
 * Close: signal the reader thread, wait for it, drain the queue, free.
 * ---------------------------------------------------------------------- */
static int pcap_close(netif_handle h)
{
    if (!h) return 0;

    h->stopping = 1;

    if (h->ops.pcap) {
        h->ops.do_breakloop(h->ops.pcap);
        /* Join reader thread before closing the pcap handle.
         * read_available is only set after pcap_setup_read() is called,
         * so check it to determine whether a reader thread was spawned. */
        if (h->read_available) {
            uv_thread_join(&h->reader);
        }
        h->ops.do_close(h->ops.pcap);
        h->ops.pcap = NULL;
    }

    /* Drain any frames that arrived before the thread exited */
    uv_mutex_lock(&h->frame_lock);
    frame_node_t *n = h->frame_head;
    h->frame_head = h->frame_tail = NULL;
    uv_mutex_unlock(&h->frame_lock);
    while (n) { frame_node_t *next = n->next; free(n); n = next; }

    uv_mutex_destroy(&h->frame_lock);
    free(h);
    return 0;
}

/* -------------------------------------------------------------------------
 * Trivial callbacks
 * ---------------------------------------------------------------------- */
static const char *pcap_get_name(netif_handle h) { return h->name; }

/* pcap driver does not manage IP routes -- no-op stubs */
static int pcap_add_route(netif_handle h, const char *dest)
    { (void)h; (void)dest; return 0; }
static int pcap_del_route(netif_handle h, const char *dest)
    { (void)h; (void)dest; return 0; }
static int pcap_exclude_rt(netif_handle h, uv_loop_t *l, const char *d)
    { (void)h; (void)l; (void)d; return 0; }

/* -------------------------------------------------------------------------
 * ziti_pcap_build_driver
 *
 * Public entry point called by platform-specific pcap open functions after
 * they have opened the pcap handle and (optionally) read the MAC address.
 * ---------------------------------------------------------------------- */
netif_driver ziti_pcap_build_driver(const char     *ifname,
                                    const pcap_ops_t *ops,
                                    const uint8_t  *hwaddr,
                                    uint8_t         hwaddr_len,
                                    char           *error,
                                    size_t          errlen)
{
    struct netif_handle_s *h = calloc(1, sizeof(*h));
    if (!h) {
        snprintf(error, errlen, "OOM allocating pcap handle");
        ops->do_close(ops->pcap);
        return NULL;
    }
    strncpy(h->name, ifname, sizeof(h->name) - 1);
    h->ops = *ops;

    uv_mutex_init(&h->frame_lock);

    struct netif_driver_s *driver = calloc(1, sizeof(*driver));
    if (!driver) {
        snprintf(error, errlen, "OOM allocating netif_driver");
        uv_mutex_destroy(&h->frame_lock);
        h->ops.do_close(h->ops.pcap);
        free(h);
        return NULL;
    }

    if (hwaddr && hwaddr_len > 0) {
        memcpy(driver->hwaddr, hwaddr, hwaddr_len);
        driver->hwaddr_len = hwaddr_len;
    }
    driver->mtu          = 1500;
    driver->handle       = h;
    driver->setup        = pcap_setup_read;
    driver->write        = pcap_write;
    driver->add_route    = pcap_add_route;
    driver->delete_route = pcap_del_route;
    driver->exclude_rt   = pcap_exclude_rt;
    driver->close        = (netif_close_cb)pcap_close;
    driver->get_name     = pcap_get_name;

    return driver;
}
