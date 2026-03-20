/*
 * rawsock_windows.c - Npcap raw Ethernet socket for dcp tools (Windows)
 *
 * Uses Npcap (wpcap.dll) loaded dynamically at runtime -- no SDK or import
 * library required.  The ifname argument is the Windows adapter friendly name
 * (e.g. "Ethernet", "Wi-Fi") as shown by Get-NetAdapter.
 *
 * Requires: Npcap runtime installed, Administrator privileges.
 */

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "rawsock.h"

#define PCAP_ERRBUF_SIZE 256
#define SNAPLEN          65536
#define READ_TIMEOUT_MS  100

/* -------------------------------------------------------------------------
 * Minimal pcap types
 * ---------------------------------------------------------------------- */
typedef struct pcap pcap_t;

struct pcap_pkthdr {
    struct { long tv_sec; long tv_usec; } ts;
    uint32_t caplen;
    uint32_t len;
};

typedef pcap_t *(*fn_pcap_open_live_t)(const char *, int, int, int, char *);
typedef int     (*fn_pcap_next_ex_t)(pcap_t *, struct pcap_pkthdr **, const unsigned char **);
typedef int     (*fn_pcap_sendpacket_t)(pcap_t *, const unsigned char *, int);
typedef char   *(*fn_pcap_geterr_t)(pcap_t *);
typedef void    (*fn_pcap_close_t)(pcap_t *);

static fn_pcap_open_live_t  dyn_pcap_open_live;
static fn_pcap_next_ex_t    dyn_pcap_next_ex;
static fn_pcap_sendpacket_t dyn_pcap_sendpacket;
static fn_pcap_geterr_t     dyn_pcap_geterr;
static fn_pcap_close_t      dyn_pcap_close;

struct rawsock_s {
    pcap_t  *pcap;
    uint8_t  mac[6];
};

/* -------------------------------------------------------------------------
 * Load Npcap DLLs and resolve function pointers
 * ---------------------------------------------------------------------- */
static int load_npcap(char *error, size_t errlen)
{
    char sys[MAX_PATH];
    GetSystemDirectoryA(sys, sizeof(sys));

    char path[MAX_PATH];
    snprintf(path, sizeof(path), "%s\\Npcap\\Packet.dll", sys);
    if (!LoadLibraryA(path)) {
        snprintf(error, errlen, "failed to load %s (err=%lu) -- is Npcap installed?",
                 path, GetLastError());
        return -1;
    }

    snprintf(path, sizeof(path), "%s\\Npcap\\wpcap.dll", sys);
    HMODULE wpcap = LoadLibraryA(path);
    if (!wpcap) {
        snprintf(error, errlen, "failed to load %s (err=%lu)", path, GetLastError());
        return -1;
    }

#define RESOLVE(name) \
    dyn_##name = (fn_##name##_t)GetProcAddress(wpcap, #name); \
    if (!dyn_##name) { \
        snprintf(error, errlen, "GetProcAddress(%s) failed", #name); \
        return -1; \
    }
    RESOLVE(pcap_open_live)
    RESOLVE(pcap_next_ex)
    RESOLVE(pcap_sendpacket)
    RESOLVE(pcap_geterr)
    RESOLVE(pcap_close)
#undef RESOLVE
    return 0;
}

/* -------------------------------------------------------------------------
 * Map Windows friendly adapter name -> NPF device path + MAC
 * ---------------------------------------------------------------------- */
static int resolve_adapter(const char *ifname,
                            char *dev_out, size_t dev_len,
                            uint8_t mac_out[6], char *error, size_t errlen)
{
    ULONG buflen = 16384;
    IP_ADAPTER_ADDRESSES *addrs = malloc(buflen);
    if (!addrs) { snprintf(error, errlen, "OOM"); return -1; }

    DWORD rc = GetAdaptersAddresses(AF_UNSPEC,
                                    GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                    GAA_FLAG_SKIP_DNS_SERVER,
                                    NULL, addrs, &buflen);
    if (rc == ERROR_BUFFER_OVERFLOW) {
        free(addrs);
        addrs = malloc(buflen);
        if (!addrs) { snprintf(error, errlen, "OOM"); return -1; }
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
                snprintf(dev_out, dev_len, "\\Device\\NPF_%s", a->AdapterName);
                if (a->PhysicalAddressLength == 6)
                    memcpy(mac_out, a->PhysicalAddress, 6);
                found = 1;
                break;
            }
        }
    }
    free(addrs);

    if (!found) {
        snprintf(error, errlen,
                 "adapter '%s' not found -- use Get-NetAdapter to list names", ifname);
        return -1;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * rawsock_open
 * ---------------------------------------------------------------------- */
rawsock_t *rawsock_open(const char *ifname, char *error, size_t errlen)
{
    WSADATA wsd;
    WSAStartup(MAKEWORD(2, 2), &wsd);

    if (!ifname || ifname[0] == '\0') {
        snprintf(error, errlen,
                 "interface name required on Windows (e.g. dcp_identify.exe \"Ethernet\")");
        return NULL;
    }

    if (load_npcap(error, errlen) != 0)
        return NULL;

    char dev[256];
    uint8_t mac[6] = {0};
    if (resolve_adapter(ifname, dev, sizeof(dev), mac, error, errlen) != 0)
        return NULL;

    char pcap_err[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = dyn_pcap_open_live(dev, SNAPLEN, 0 /* not promiscuous */,
                                       READ_TIMEOUT_MS, pcap_err);
    if (!pcap) {
        snprintf(error, errlen, "pcap_open_live(%s): %s", dev, pcap_err);
        return NULL;
    }

    rawsock_t *rs = calloc(1, sizeof(*rs));
    if (!rs) {
        snprintf(error, errlen, "OOM");
        dyn_pcap_close(pcap);
        return NULL;
    }
    rs->pcap = pcap;
    memcpy(rs->mac, mac, 6);
    return rs;
}

void rawsock_close(rawsock_t *rs)
{
    if (!rs) return;
    if (rs->pcap) dyn_pcap_close(rs->pcap);
    free(rs);
}

int rawsock_send(rawsock_t *rs, const uint8_t *frame, size_t len)
{
    if (dyn_pcap_sendpacket(rs->pcap, frame, (int)len) != 0) {
        fprintf(stderr, "pcap_sendpacket: %s\n", dyn_pcap_geterr(rs->pcap));
        return -1;
    }
    return 0;
}

int rawsock_recv(rawsock_t *rs, uint8_t *buf, size_t buflen, int timeout_ms)
{
    /* pcap was opened with READ_TIMEOUT_MS; poll in small slices */
    int remaining = (timeout_ms > 0) ? timeout_ms : 3000;

    while (remaining > 0) {
        struct pcap_pkthdr *hdr;
        const unsigned char *data;
        int rc = dyn_pcap_next_ex(rs->pcap, &hdr, &data);
        if (rc == 1) {
            size_t copy = hdr->caplen < buflen ? hdr->caplen : buflen;
            memcpy(buf, data, copy);
            return (int)copy;
        }
        if (rc < 0) return -1;
        /* rc == 0: timeout slice elapsed */
        remaining -= READ_TIMEOUT_MS;
    }
    return 0; /* timed out */
}

void rawsock_get_mac(rawsock_t *rs, uint8_t mac[6])
{
    memcpy(mac, rs->mac, 6);
}
