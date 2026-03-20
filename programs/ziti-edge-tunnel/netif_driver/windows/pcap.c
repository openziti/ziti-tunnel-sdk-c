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
 * pcap.c - Npcap L2 netif driver for ziti-edge-tunnel (Windows)
 *
 * Opens a physical network adapter by friendly name using Npcap.  All pcap
 * functions are resolved at runtime via GetProcAddress from the installed
 * wpcap.dll (C:\Windows\System32\Npcap\wpcap.dll) so no import library or
 * SDK is required -- only a standard Npcap runtime installation.
 *
 * Requires: Npcap installed, Administrator privileges.
 */

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <ziti/netif_driver.h>
#include <ziti/ziti_log.h>

#include "pcap.h"

#define MAX_FRAME_LEN    65536u
#define PCAP_READ_TIMEOUT_MS 500
#define PCAP_ERRBUF_SIZE 256

/* -------------------------------------------------------------------------
 * Minimal pcap types (avoids dependency on pcap.h / Npcap SDK)
 * ---------------------------------------------------------------------- */
typedef struct pcap pcap_t;

struct pcap_pkthdr {
    struct { long tv_sec; long tv_usec; } ts;
    uint32_t caplen;
    uint32_t len;
};

/* -------------------------------------------------------------------------
 * Function pointers resolved from wpcap.dll
 * ---------------------------------------------------------------------- */
typedef pcap_t *(*fn_pcap_open_live_t)(const char *dev, int snaplen, int promisc,
                                        int to_ms, char *errbuf);
typedef int     (*fn_pcap_next_ex_t)(pcap_t *p, struct pcap_pkthdr **hdr,
                                      const unsigned char **data);
typedef int     (*fn_pcap_sendpacket_t)(pcap_t *p, const unsigned char *buf, int size);
typedef char   *(*fn_pcap_geterr_t)(pcap_t *p);
typedef void    (*fn_pcap_close_t)(pcap_t *p);
typedef void    (*fn_pcap_breakloop_t)(pcap_t *p);

static fn_pcap_open_live_t   dyn_pcap_open_live;
static fn_pcap_next_ex_t     dyn_pcap_next_ex;
static fn_pcap_sendpacket_t  dyn_pcap_sendpacket;
static fn_pcap_geterr_t      dyn_pcap_geterr;
static fn_pcap_close_t       dyn_pcap_close;
static fn_pcap_breakloop_t   dyn_pcap_breakloop;

/* -------------------------------------------------------------------------
 * Internal frame queue (reader thread -> libuv async)
 * ---------------------------------------------------------------------- */
typedef struct frame_node {
    size_t len;
    struct frame_node *next;
    uint8_t data[1];
} frame_node_t;

/* -------------------------------------------------------------------------
 * netif_handle
 * ---------------------------------------------------------------------- */
struct netif_handle_s {
    char     name[256];
    pcap_t  *pcap;

    volatile LONG stopping;

    uv_thread_t  reader;
    uv_async_t  *read_available;

    uv_mutex_t   frame_lock;
    frame_node_t *frame_head;
    frame_node_t *frame_tail;

    packet_cb on_packet;
    void     *netif;
};

/* -------------------------------------------------------------------------
 * Load wpcap.dll from the Npcap installation directory and resolve all
 * function pointers.  Returns 0 on success, -1 on failure.
 * ---------------------------------------------------------------------- */
static int load_npcap(char *error, size_t errlen)
{
    char sys[MAX_PATH];
    GetSystemDirectoryA(sys, sizeof(sys));

    char packet_path[MAX_PATH], wpcap_path[MAX_PATH];
    snprintf(packet_path, sizeof(packet_path), "%s\\Npcap\\Packet.dll", sys);
    snprintf(wpcap_path,  sizeof(wpcap_path),  "%s\\Npcap\\wpcap.dll",  sys);

    /* Packet.dll must be loaded first (wpcap.dll depends on it) */
    if (!LoadLibraryA(packet_path)) {
        snprintf(error, errlen, "failed to load %s (err=%lu) -- is Npcap installed?",
                 packet_path, GetLastError());
        return -1;
    }
    ZITI_LOG(DEBUG, "pcap: loaded %s", packet_path);

    HMODULE wpcap = LoadLibraryA(wpcap_path);
    if (!wpcap) {
        snprintf(error, errlen, "failed to load %s (err=%lu)", wpcap_path, GetLastError());
        return -1;
    }
    ZITI_LOG(DEBUG, "pcap: loaded %s", wpcap_path);

#define RESOLVE(name) \
    dyn_##name = (fn_##name##_t)GetProcAddress(wpcap, #name); \
    if (!dyn_##name) { \
        snprintf(error, errlen, "GetProcAddress(%s) failed (err=%lu)", #name, GetLastError()); \
        return -1; \
    } \
    ZITI_LOG(DEBUG, "pcap: resolved %s", #name)

    RESOLVE(pcap_open_live);
    RESOLVE(pcap_next_ex);
    RESOLVE(pcap_sendpacket);
    RESOLVE(pcap_geterr);
    RESOLVE(pcap_close);
    RESOLVE(pcap_breakloop);
#undef RESOLVE

    return 0;
}

/* -------------------------------------------------------------------------
 * Resolve friendly name -> adapter GUID via GetAdaptersAddresses
 * ---------------------------------------------------------------------- */
static int friendly_name_to_guid(const char *ifname, char *guid_out, size_t guid_out_len)
{
    ULONG buflen = 16384;
    IP_ADAPTER_ADDRESSES *addrs = malloc(buflen);
    if (!addrs) return -1;

    DWORD rc = GetAdaptersAddresses(AF_UNSPEC,
                                    GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                    GAA_FLAG_SKIP_DNS_SERVER,
                                    NULL, addrs, &buflen);
    if (rc == ERROR_BUFFER_OVERFLOW) {
        free(addrs);
        addrs = malloc(buflen);
        if (!addrs) return -1;
        rc = GetAdaptersAddresses(AF_UNSPEC,
                                  GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                  GAA_FLAG_SKIP_DNS_SERVER,
                                  NULL, addrs, &buflen);
    }

    int found = 0;
    if (rc == NO_ERROR) {
        for (IP_ADAPTER_ADDRESSES *a = addrs; a; a = a->Next) {
            char friendly[256] = {0};
            WideCharToMultiByte(CP_UTF8, 0, a->FriendlyName, -1,
                                friendly, sizeof(friendly), NULL, NULL);
            if (_stricmp(friendly, ifname) == 0) {
                strncpy_s(guid_out, guid_out_len, a->AdapterName, _TRUNCATE);
                found = 1;
                ZITI_LOG(INFO, "pcap: '%s' -> GUID %s", ifname, guid_out);
                break;
            }
        }
    }
    free(addrs);
    return found ? 0 : -1;
}

/* -------------------------------------------------------------------------
 * Read MAC from the adapter via GetAdaptersAddresses
 * ---------------------------------------------------------------------- */
static void read_hwaddr(const char *ifname, uint8_t hwaddr[6], uint8_t *hwaddr_len)
{
    ULONG buflen = 16384;
    IP_ADAPTER_ADDRESSES *addrs = malloc(buflen);
    if (!addrs) return;

    DWORD rc = GetAdaptersAddresses(AF_UNSPEC,
                                    GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                    GAA_FLAG_SKIP_DNS_SERVER,
                                    NULL, addrs, &buflen);
    if (rc == ERROR_BUFFER_OVERFLOW) {
        free(addrs);
        addrs = malloc(buflen);
        if (!addrs) return;
        rc = GetAdaptersAddresses(AF_UNSPEC,
                                  GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                  GAA_FLAG_SKIP_DNS_SERVER,
                                  NULL, addrs, &buflen);
    }

    if (rc == NO_ERROR) {
        for (IP_ADAPTER_ADDRESSES *a = addrs; a; a = a->Next) {
            char friendly[256] = {0};
            WideCharToMultiByte(CP_UTF8, 0, a->FriendlyName, -1,
                                friendly, sizeof(friendly), NULL, NULL);
            if (_stricmp(friendly, ifname) == 0) {
                if (a->PhysicalAddressLength == 6) {
                    memcpy(hwaddr, a->PhysicalAddress, 6);
                    *hwaddr_len = 6;
                    ZITI_LOG(INFO, "pcap: hwaddr %02x:%02x:%02x:%02x:%02x:%02x",
                             hwaddr[0], hwaddr[1], hwaddr[2],
                             hwaddr[3], hwaddr[4], hwaddr[5]);
                }
                break;
            }
        }
    }
    free(addrs);
}

/* -------------------------------------------------------------------------
 * Frame delivery: called on the libuv event loop thread via uv_async_t
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
 * Reader thread: pcap_next_ex loop, queues frames for libuv delivery
 * ---------------------------------------------------------------------- */
static void pcap_reader_thread(void *arg)
{
    netif_handle h = arg;
    struct pcap_pkthdr *hdr;
    const unsigned char *data;

    ZITI_LOG(DEBUG, "pcap: reader thread started");

    while (!InterlockedCompareExchange(&h->stopping, 0, 0)) {
        int rc = dyn_pcap_next_ex(h->pcap, &hdr, &data);
        if (rc == 0) continue;   /* read timeout -- check stopping flag */
        if (rc < 0) {
            if (!InterlockedCompareExchange(&h->stopping, 0, 0)) {
                ZITI_LOG(ERROR, "pcap: pcap_next_ex error: %s", dyn_pcap_geterr(h->pcap));
            }
            break;
        }

        if (hdr->caplen == 0) continue;

        frame_node_t *node = malloc(offsetof(frame_node_t, data) + hdr->caplen);
        if (!node) {
            ZITI_LOG(ERROR, "pcap: OOM dropping frame of %u bytes", hdr->caplen);
            continue;
        }
        node->len  = hdr->caplen;
        node->next = NULL;
        memcpy(node->data, data, hdr->caplen);

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

    ZITI_LOG(DEBUG, "pcap: reader thread exiting");
}

/* -------------------------------------------------------------------------
 * setup_read: spawn reader thread and wire up async handle
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
 * Write: inject frame onto the wire via pcap_sendpacket
 * ---------------------------------------------------------------------- */
static ssize_t pcap_write(netif_handle h, const void *buf, size_t len)
{
    if (dyn_pcap_sendpacket(h->pcap, (const unsigned char *)buf, (int)len) != 0) {
        ZITI_LOG(ERROR, "pcap: pcap_sendpacket failed: %s", dyn_pcap_geterr(h->pcap));
        return -1;
    }
    return (ssize_t)len;
}

/* -------------------------------------------------------------------------
 * Close
 * ---------------------------------------------------------------------- */
static int ziti_pcap_close(netif_handle h)
{
    if (!h) return 0;

    InterlockedExchange(&h->stopping, 1);

    if (h->pcap) {
        dyn_pcap_breakloop(h->pcap);
        dyn_pcap_close(h->pcap);
        h->pcap = NULL;
    }

    uv_mutex_lock(&h->frame_lock);
    frame_node_t *n = h->frame_head;
    h->frame_head = h->frame_tail = NULL;
    uv_mutex_unlock(&h->frame_lock);
    while (n) { frame_node_t *next = n->next; free(n); n = next; }

    uv_mutex_destroy(&h->frame_lock);
    free(h);
    return 0;
}

static const char *pcap_get_name(netif_handle h) { return h->name; }

/* no-op stubs -- pcap driver does not manage IP routes */
static int pcap_add_route(netif_handle h, const char *dest)    { (void)h; (void)dest; return 0; }
static int pcap_del_route(netif_handle h, const char *dest)    { (void)h; (void)dest; return 0; }
static int pcap_exclude_rt(netif_handle h, uv_loop_t *l, const char *d) {
    (void)h; (void)l; (void)d; return 0;
}

/* -------------------------------------------------------------------------
 * ziti_pcap_open
 * ---------------------------------------------------------------------- */
netif_driver ziti_pcap_open(uv_loop_t *loop, const char *ifname,
                             char *error, size_t error_len)
{
    if (error) memset(error, 0, error_len);

    if (load_npcap(error, error_len) != 0) {
        return NULL;
    }

    char guid[64] = {0};
    if (friendly_name_to_guid(ifname, guid, sizeof(guid)) != 0) {
        snprintf(error, error_len,
                 "adapter '%s' not found -- check name with Get-NetAdapter", ifname);
        return NULL;
    }

    char dev_name[128];
    snprintf(dev_name, sizeof(dev_name), "\\Device\\NPF_%s", guid);
    ZITI_LOG(INFO, "pcap: opening '%s' (%s)", ifname, dev_name);

    char pcap_err[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = dyn_pcap_open_live(dev_name, MAX_FRAME_LEN,
                                       0 /* not promiscuous */,
                                       PCAP_READ_TIMEOUT_MS, pcap_err);
    if (!pcap) {
        ZITI_LOG(ERROR, "pcap: pcap_open_live failed: %s", pcap_err);
        snprintf(error, error_len, "pcap_open_live failed: %s", pcap_err);
        return NULL;
    }
    ZITI_LOG(INFO, "pcap: opened adapter '%s'", ifname);

    struct netif_handle_s *h = calloc(1, sizeof(*h));
    if (!h) {
        snprintf(error, error_len, "OOM");
        dyn_pcap_close(pcap);
        return NULL;
    }
    strncpy_s(h->name, sizeof(h->name), ifname, _TRUNCATE);
    h->pcap = pcap;

    struct netif_driver_s *driver = calloc(1, sizeof(*driver));
    if (!driver) {
        snprintf(error, error_len, "OOM");
        dyn_pcap_close(pcap);
        free(h);
        return NULL;
    }

    read_hwaddr(ifname, driver->hwaddr, &driver->hwaddr_len);
    if (driver->hwaddr_len == 0) {
        ZITI_LOG(WARN, "pcap: could not read hwaddr for '%s' -- L2 may not work", ifname);
    }

    driver->mtu = 1500;

    uv_mutex_init(&h->frame_lock);

    driver->handle       = h;
    driver->setup        = pcap_setup_read;
    driver->write        = pcap_write;
    driver->add_route    = pcap_add_route;
    driver->delete_route = pcap_del_route;
    driver->exclude_rt   = pcap_exclude_rt;
    driver->close        = (netif_close_cb)ziti_pcap_close;
    driver->get_name     = pcap_get_name;

    return driver;
}
