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
 * pcap.c - libpcap L2 netif driver for ziti-edge-tunnel (Linux).
 *
 * Opens a physical network adapter by interface name using libpcap.  All
 * pcap functions are resolved at runtime via dlopen/dlsym so no link-time
 * dependency on libpcap is required -- only a standard libpcap runtime
 * installation.
 *
 * Generic pcap logic (reader thread, frame queue, async delivery) lives in
 * netif_driver/pcap_common.c.  This file contains only Linux-specific
 * code: dynamic library loading, MAC address discovery via
 * ioctl(SIOCGIFHWADDR), and thin wrappers adapting libpcap to pcap_ops_t.
 *
 * Requires: libpcap installed at runtime, CAP_NET_RAW capability (or root).
 */

#include <pcap/pcap.h>

#include <dlfcn.h>
#include <errno.h>
#include <net/if.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <ziti/netif_driver.h>
#include <ziti/ziti_log.h>

#include "../pcap_common.h"
#include "pcap.h"

#define MAX_FRAME_LEN        65536
#define PCAP_READ_TIMEOUT_MS 500

/* -------------------------------------------------------------------------
 * Function pointers resolved from libpcap.so at runtime
 * ---------------------------------------------------------------------- */
typedef pcap_t *(*fn_pcap_open_live_t)(const char *dev, int snaplen, int promisc,
                                        int to_ms, char *errbuf);
typedef int     (*fn_pcap_next_ex_t)(pcap_t *p, struct pcap_pkthdr **hdr,
                                      const u_char **data);
typedef int     (*fn_pcap_sendpacket_t)(pcap_t *p, const u_char *buf, int size);
typedef char   *(*fn_pcap_geterr_t)(pcap_t *p);
typedef void    (*fn_pcap_close_t)(pcap_t *p);
typedef void    (*fn_pcap_breakloop_t)(pcap_t *p);
typedef int     (*fn_pcap_compile_t)(pcap_t *p, struct bpf_program *fp,
                                      const char *str, int optimize, bpf_u_int32 netmask);
typedef int     (*fn_pcap_setfilter_t)(pcap_t *p, struct bpf_program *fp);
typedef void    (*fn_pcap_freecode_t)(struct bpf_program *fp);

static fn_pcap_open_live_t   dyn_pcap_open_live;
static fn_pcap_next_ex_t     dyn_pcap_next_ex;
static fn_pcap_sendpacket_t  dyn_pcap_sendpacket;
static fn_pcap_geterr_t      dyn_pcap_geterr;
static fn_pcap_close_t       dyn_pcap_close;
static fn_pcap_breakloop_t   dyn_pcap_breakloop;
static fn_pcap_compile_t     dyn_pcap_compile;
static fn_pcap_setfilter_t   dyn_pcap_setfilter;
static fn_pcap_freecode_t    dyn_pcap_freecode;

/* -------------------------------------------------------------------------
 * Load libpcap.so at runtime and resolve all function pointers.
 * Returns 0 on success, -1 on failure.
 * ---------------------------------------------------------------------- */
static int load_libpcap(char *error, size_t errlen)
{
    /* Try versioned name first, then unversioned fallback */
    static const char *candidates[] = { "libpcap.so.1", "libpcap.so", NULL };

    void *lib = NULL;
    for (int i = 0; candidates[i] != NULL; i++) {
        lib = dlopen(candidates[i], RTLD_LAZY | RTLD_LOCAL);
        if (lib) {
            ZITI_LOG(DEBUG, "pcap: loaded %s", candidates[i]);
            break;
        }
    }

    if (!lib) {
        snprintf(error, errlen,
                 "failed to load libpcap (%s) -- is libpcap installed?", dlerror());
        return -1;
    }

#define RESOLVE(name) \
    dyn_##name = (fn_##name##_t)dlsym(lib, #name); \
    if (!dyn_##name) { \
        snprintf(error, errlen, "dlsym(%s) failed: %s", #name, dlerror()); \
        return -1; \
    } \
    ZITI_LOG(DEBUG, "pcap: resolved %s", #name)

    RESOLVE(pcap_open_live);
    RESOLVE(pcap_next_ex);
    RESOLVE(pcap_sendpacket);
    RESOLVE(pcap_geterr);
    RESOLVE(pcap_close);
    RESOLVE(pcap_breakloop);
    RESOLVE(pcap_compile);
    RESOLVE(pcap_setfilter);
    RESOLVE(pcap_freecode);
#undef RESOLVE

    return 0;
}

/* -------------------------------------------------------------------------
 * Read the MAC address of a Linux network interface via ioctl(SIOCGIFHWADDR).
 * ---------------------------------------------------------------------- */
static void read_hwaddr_linux(const char *ifname, uint8_t hwaddr[6], uint8_t *hwaddr_len)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        ZITI_LOG(WARN, "pcap: socket() failed reading hwaddr for '%s': %s",
                 ifname, strerror(errno));
        return;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        ZITI_LOG(WARN, "pcap: SIOCGIFHWADDR(%s) failed: %s", ifname, strerror(errno));
        close(sock);
        return;
    }
    close(sock);

    memcpy(hwaddr, ifr.ifr_hwaddr.sa_data, 6);
    *hwaddr_len = 6;

    ZITI_LOG(INFO, "pcap: hwaddr %02x:%02x:%02x:%02x:%02x:%02x",
             hwaddr[0], hwaddr[1], hwaddr[2],
             hwaddr[3], hwaddr[4], hwaddr[5]);
}

/* -------------------------------------------------------------------------
 * pcap_ops_t wrapper functions
 *
 * Thin wrappers that adapt the dynamically-loaded libpcap function pointers
 * to the platform-neutral pcap_ops_t interface expected by pcap_common.c.
 * ---------------------------------------------------------------------- */
static int lnx_set_filter(void *p, const char *expr)
{
    struct bpf_program bpf;
    if (dyn_pcap_compile((pcap_t *)p, &bpf, expr, 1, PCAP_NETMASK_UNKNOWN) != 0) {
        ZITI_LOG(WARN, "pcap: pcap_compile(\"%s\") failed: %s",
                 expr, dyn_pcap_geterr((pcap_t *)p));
        return -1;
    }
    int rc = dyn_pcap_setfilter((pcap_t *)p, &bpf);
    if (rc != 0) {
        ZITI_LOG(WARN, "pcap: pcap_setfilter failed: %s", dyn_pcap_geterr((pcap_t *)p));
    }
    dyn_pcap_freecode(&bpf);
    return rc;
}

static int lnx_next_packet(void *p, uint32_t *caplen, const unsigned char **data)
{
    struct pcap_pkthdr *hdr = NULL;
    int rc = dyn_pcap_next_ex((pcap_t *)p, &hdr, (const u_char **)data);
    if (rc == 1 && hdr) *caplen = hdr->caplen;
    return rc;
}

static int lnx_send_packet(void *p, const unsigned char *buf, int size)
{
    return dyn_pcap_sendpacket((pcap_t *)p, (const u_char *)buf, size);
}

static char *lnx_get_error(void *p)   { return dyn_pcap_geterr((pcap_t *)p); }
static void  lnx_do_breakloop(void *p){ dyn_pcap_breakloop((pcap_t *)p); }
static void  lnx_do_close(void *p)    { dyn_pcap_close((pcap_t *)p); }

/* -------------------------------------------------------------------------
 * ziti_pcap_open
 * ---------------------------------------------------------------------- */
netif_driver ziti_pcap_open(uv_loop_t *loop, const char *ifname,
                             char *error, size_t error_len)
{
    (void)loop; /* loop is not needed during open; used later by setup callback */

    if (error) memset(error, 0, error_len);

    if (load_libpcap(error, error_len) != 0) {
        return NULL;
    }

    char pcap_err[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = dyn_pcap_open_live(ifname, MAX_FRAME_LEN,
                                       0 /* not promiscuous */,
                                       PCAP_READ_TIMEOUT_MS, pcap_err);
    if (!pcap) {
        ZITI_LOG(ERROR, "pcap: pcap_open_live failed: %s", pcap_err);
        snprintf(error, error_len, "pcap_open_live(%s) failed: %s", ifname, pcap_err);
        return NULL;
    }
    ZITI_LOG(INFO, "pcap: opened interface '%s'", ifname);

    uint8_t hwaddr[6] = {0};
    uint8_t hwaddr_len = 0;
    read_hwaddr_linux(ifname, hwaddr, &hwaddr_len);
    if (hwaddr_len == 0) {
        ZITI_LOG(WARN, "pcap: could not read hwaddr for '%s' -- L2 may not work", ifname);
    }

    pcap_ops_t ops = {
        .pcap         = pcap,
        .next_packet  = lnx_next_packet,
        .send_packet  = lnx_send_packet,
        .get_error    = lnx_get_error,
        .do_breakloop = lnx_do_breakloop,
        .do_close     = lnx_do_close,
        .set_filter   = lnx_set_filter,
    };

    return ziti_pcap_build_driver(ifname, &ops, hwaddr, hwaddr_len, error, error_len);
}
