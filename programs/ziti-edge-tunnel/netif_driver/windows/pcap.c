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
 * pcap.c - Npcap L2 netif driver for ziti-edge-tunnel (Windows).
 *
 * Opens a physical network adapter by friendly name using Npcap.  All pcap
 * functions are resolved at runtime via GetProcAddress from the installed
 * wpcap.dll (C:\Windows\System32\Npcap\wpcap.dll) so no import library or
 * SDK is required -- only a standard Npcap runtime installation.
 *
 * Generic pcap logic (reader thread, frame queue, async delivery) lives in
 * netif_driver/pcap_common.c.  This file contains only Windows-specific
 * code: DLL loading, friendly-name-to-GUID resolution, and MAC discovery.
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

#include "../pcap_common.h"
#include "pcap.h"

#define MAX_FRAME_LEN       65536u
#define PCAP_READ_TIMEOUT_MS 500
#define PCAP_ERRBUF_SIZE    256

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
 * pcap_ops_t wrapper functions
 *
 * Thin wrappers that adapt the dynamically-loaded Npcap function pointers
 * to the platform-neutral pcap_ops_t interface expected by pcap_common.c.
 * ---------------------------------------------------------------------- */
static int win_next_packet(void *p, uint32_t *caplen, const unsigned char **data)
{
    struct pcap_pkthdr *hdr = NULL;
    int rc = dyn_pcap_next_ex((pcap_t *)p, &hdr, data);
    if (rc == 1 && hdr) *caplen = hdr->caplen;
    return rc;
}

static int win_send_packet(void *p, const unsigned char *buf, int size)
{
    return dyn_pcap_sendpacket((pcap_t *)p, buf, size);
}

static char *win_get_error(void *p)   { return dyn_pcap_geterr((pcap_t *)p); }
static void  win_do_breakloop(void *p){ dyn_pcap_breakloop((pcap_t *)p); }
static void  win_do_close(void *p)    { dyn_pcap_close((pcap_t *)p); }

/* -------------------------------------------------------------------------
 * ziti_pcap_open
 * ---------------------------------------------------------------------- */
netif_driver ziti_pcap_open(uv_loop_t *loop, const char *ifname,
                             char *error, size_t error_len)
{
    (void)loop; /* loop is not needed during open; used later by setup callback */

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

    uint8_t hwaddr[6] = {0};
    uint8_t hwaddr_len = 0;
    read_hwaddr(ifname, hwaddr, &hwaddr_len);
    if (hwaddr_len == 0) {
        ZITI_LOG(WARN, "pcap: could not read hwaddr for '%s' -- L2 may not work", ifname);
    }

    pcap_ops_t ops = {
        .pcap         = pcap,
        .next_packet  = win_next_packet,
        .send_packet  = win_send_packet,
        .get_error    = win_get_error,
        .do_breakloop = win_do_breakloop,
        .do_close     = win_do_close,
    };

    return ziti_pcap_build_driver(ifname, &ops, hwaddr, hwaddr_len, error, error_len);
}
