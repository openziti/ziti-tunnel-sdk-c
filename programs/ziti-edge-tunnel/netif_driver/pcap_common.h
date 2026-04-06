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
 * pcap_common.h - Platform-neutral pcap L2 netif driver internals.
 *
 * Shared between the Windows (Npcap) and Linux (libpcap) pcap drivers.
 * Contains no OS-specific headers.
 */

#ifndef ZITI_TUNNEL_SDK_C_PCAP_COMMON_H
#define ZITI_TUNNEL_SDK_C_PCAP_COMMON_H

#include <stdint.h>
#include <stddef.h>

#include <uv.h>
#include <ziti/netif_driver.h>

/* -------------------------------------------------------------------------
 * frame_node_t: singly-linked list node for the reader-thread -> event-loop
 * packet queue.
 * ---------------------------------------------------------------------- */
typedef struct frame_node {
    size_t             len;
    struct frame_node *next;
    uint8_t            data[1]; /* flexible member pattern */
} frame_node_t;

/* -------------------------------------------------------------------------
 * pcap_ops_t: platform-supplied vtable over an opaque pcap handle.
 *
 * The platform-specific pcap.c fills this struct and passes it to
 * ziti_pcap_build_driver().  Using a vtable keeps all pcap type definitions
 * (pcap_t, pcap_pkthdr, ...) inside the platform file so that pcap_common.c
 * never needs to include <pcap/pcap.h> or any OS SDK header.
 * ---------------------------------------------------------------------- */
typedef struct pcap_ops_s {
    void  *pcap;   /* opaque pcap_t * -- owned by this struct after open */

    /* Read the next captured packet.
     * Returns: 1 = packet available (*caplen and *data filled in),
     *          0 = read timeout (no packet, try again),
     *         <0 = unrecoverable error.
     * Called only from the reader thread. */
    int   (*next_packet)(void *pcap, uint32_t *caplen, const unsigned char **data);

    /* Inject a frame onto the wire.
     * Returns 0 on success, non-zero on failure.
     * Called from the libuv event-loop thread. */
    int   (*send_packet)(void *pcap, const unsigned char *buf, int size);

    /* Return a NUL-terminated error string.  Caller must not free it. */
    char *(*get_error)  (void *pcap);

    /* Unblock a blocking next_packet call.  Must be safe to call from any
     * thread (including the libuv event-loop thread). */
    void  (*do_breakloop)(void *pcap);

    /* Release the pcap handle.  Called after do_breakloop + thread join. */
    void  (*do_close)   (void *pcap);
} pcap_ops_t;

/* -------------------------------------------------------------------------
 * struct netif_handle_s: the runtime state for a pcap-based netif driver.
 *
 * Defined here (not in the platform headers) so that pcap_common.c can
 * allocate and populate it without the platform file needing to know its
 * layout.  Platform files only hold a pointer to netif_driver_t.
 *
 * NOTE: linux/tun.c also defines struct netif_handle_s for the TUN/TAP
 * driver, but in its own translation unit.  There is no conflict as long as
 * linux/pcap.c does not include linux/tun.h.
 * ---------------------------------------------------------------------- */
struct netif_handle_s {
    char         name[256];

    pcap_ops_t   ops;            /* copy of the platform vtable */

    volatile int stopping;       /* set to 1 to signal reader thread exit */

    uv_thread_t  reader;         /* background capture thread */
    uv_async_t  *read_available; /* wakes the event loop when frames arrive */

    uv_mutex_t   frame_lock;     /* protects frame_head / frame_tail */
    frame_node_t *frame_head;
    frame_node_t *frame_tail;

    packet_cb    on_packet;      /* lwIP delivery callback */
    void        *netif;          /* lwIP netif pointer */
};

/* -------------------------------------------------------------------------
 * ziti_pcap_build_driver
 *
 * Allocates and fully wires a netif_driver from an already-opened pcap
 * session.  The caller (platform-specific pcap.c) has already:
 *   - opened the pcap handle (e.g. via pcap_open_live)
 *   - read the interface hardware address
 *   - filled in all function pointers in *ops
 *
 * The driver's setup callback installs the uv_async handle and spawns the
 * reader thread when the tunneler is ready; the loop is NOT touched here.
 *
 * @param ifname      Logical name stored in the handle (used by get_name).
 * @param ops         Filled vtable including the opaque pcap handle.
 * @param hwaddr      Hardware (MAC) address bytes, or NULL if unavailable.
 * @param hwaddr_len  Number of valid bytes in hwaddr (0 if unavailable).
 * @param error       Buffer to receive an error message on failure.
 * @param errlen      Size of the error buffer.
 * @return            Heap-allocated netif_driver on success, NULL on failure.
 * ---------------------------------------------------------------------- */
netif_driver ziti_pcap_build_driver(const char     *ifname,
                                    const pcap_ops_t *ops,
                                    const uint8_t  *hwaddr,
                                    uint8_t         hwaddr_len,
                                    char           *error,
                                    size_t          errlen);

#endif /* ZITI_TUNNEL_SDK_C_PCAP_COMMON_H */
