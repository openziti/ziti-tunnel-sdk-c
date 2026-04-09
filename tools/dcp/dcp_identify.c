/*
 * dcp_identify.c - Send a PROFINET DCP Identify broadcast (or unicast) and
 *                  print responses.  Optionally set station name and/or IP on
 *                  each responding device.
 *
 * Build: see CMakeLists.txt in this directory, or for a quick Linux one-liner:
 *   gcc -o dcp_identify dcp_identify.c rawsock_linux.c
 *
 * Run:
 *   Linux/macOS : sudo ./dcp_identify eth0
 *   Windows     : dcp_identify.exe   (interface arg ignored; uses first TAP adapter)
 *
 * Options:
 *   [ifname]              network interface (default: first available)
 *   -t <mac>              send unicast identify to this MAC instead of broadcast
 *   -n <name>             after identify, SET station name on each found device
 *   -i <ip>[/<mask>[/gw]] after identify, SET IP config on each found device
 */

#include "dcp_common.h"
#include "rawsock.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* devices discovered during the identify phase */
#define MAX_DEVICES 32
static uint8_t g_found_macs[MAX_DEVICES][6];
static int     g_found_count = 0;

/* ---------- helpers ---------- */

static int parse_mac(const char *s, uint8_t mac[6])
{
    unsigned v[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x", &v[0],&v[1],&v[2],&v[3],&v[4],&v[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++) mac[i] = (uint8_t)v[i];
    return 0;
}

static int parse_ip4(const char *s, uint8_t ip[4])
{
    unsigned a, b, c, d;
    if (sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return -1;
    ip[0] = (uint8_t)a; ip[1] = (uint8_t)b; ip[2] = (uint8_t)c; ip[3] = (uint8_t)d;
    return 0;
}

/* Parse "ip[/mask[/gw]]". mask defaults to 255.255.255.0; gw to 0.0.0.0. */
static int parse_ip_arg(const char *s, uint8_t ip[4], uint8_t mask[4], uint8_t gw[4])
{
    char buf[64];
    strncpy(buf, s, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    mask[0] = 255; mask[1] = 255; mask[2] = 255; mask[3] = 0;
    memset(gw, 0, 4);

    char *slash1 = strchr(buf, '/');
    char *slash2 = slash1 ? strchr(slash1 + 1, '/') : NULL;
    if (slash1) *slash1 = '\0';
    if (slash2) *slash2 = '\0';

    if (parse_ip4(buf, ip) < 0) return -1;
    if (slash1 && parse_ip4(slash1 + 1, mask) < 0) return -1;
    if (slash2 && parse_ip4(slash2 + 1, gw) < 0) return -1;
    return 0;
}

/* ---------- identify response ---------- */

static int parse_ident_response(const uint8_t *buf, int len)
{
    if (len < (int)(sizeof(eth_hdr_t) + sizeof(dcp_hdr_t))) return 0;

    const eth_hdr_t *eth = (const eth_hdr_t *)buf;
    const dcp_hdr_t *dcp = (const dcp_hdr_t *)(buf + sizeof(eth_hdr_t));

    if (DCP_NTOHS(eth->ethertype) != ETH_P_PROFINET)         return 0;
    if (DCP_NTOHS(dcp->frame_id)  != DCP_FRAME_ID_IDENT_RSP) return 0;
    if (dcp->service_id   != DCP_SVC_IDENTIFY)                return 0;
    if (dcp->service_type != DCP_SVCTYPE_RESPONSE)            return 0;

    printf("  device ");
    print_mac(eth->src);
    printf("  xid=0x%08x\n", DCP_NTOHL(dcp->xid));

    const uint8_t *p     = buf + sizeof(eth_hdr_t) + sizeof(dcp_hdr_t);
    int            rem   = DCP_NTOHS(dcp->dcp_data_len);
    int            avail = len - (int)(sizeof(eth_hdr_t) + sizeof(dcp_hdr_t));
    if (rem > avail) rem = avail;

    while (rem >= (int)sizeof(dcp_blk_t)) {
        const dcp_blk_t *b    = (const dcp_blk_t *)p;
        uint16_t         blen = DCP_NTOHS(b->block_len);
        p   += sizeof(dcp_blk_t);
        rem -= sizeof(dcp_blk_t);
        if (blen > rem) break;

        if (b->option == DCP_OPT_DEVICE && b->suboption == DCP_SUB_DEVICE_NAME && blen > 2)
            printf("    station-name : %.*s\n", (int)(blen - 2), p + 2);
        else if (b->option == DCP_OPT_DEVICE && b->suboption == DCP_SUB_DEVICE_VENDOR && blen > 2)
            printf("    vendor       : %.*s\n", (int)(blen - 2), p + 2);
        else if (b->option == DCP_OPT_IP && b->suboption == DCP_SUB_IP_ADDR && blen >= 14)
            printf("    ip/mask/gw   : %u.%u.%u.%u / %u.%u.%u.%u / %u.%u.%u.%u\n",
                   p[2],p[3],p[4],p[5], p[6],p[7],p[8],p[9], p[10],p[11],p[12],p[13]);

        int adv = blen + (blen & 1);
        p   += adv;
        rem -= adv;
    }

    /* record this device for the SET phase */
    if (g_found_count < MAX_DEVICES)
        memcpy(g_found_macs[g_found_count++], eth->src, 6);

    return 1;
}

/* ---------- set phase ---------- */

/* Returns 1 if the frame is a SET response matching xid from target_mac. */
static int parse_set_response(const uint8_t *buf, int len,
                               const uint8_t target_mac[6], uint32_t xid)
{
    if (len < (int)(sizeof(eth_hdr_t) + sizeof(dcp_hdr_t))) return 0;

    const eth_hdr_t *eth = (const eth_hdr_t *)buf;
    const dcp_hdr_t *dcp = (const dcp_hdr_t *)(buf + sizeof(eth_hdr_t));

    if (DCP_NTOHS(eth->ethertype) != ETH_P_PROFINET)       return 0;
    if (memcmp(eth->src, target_mac, 6) != 0)              return 0;
    if (DCP_NTOHS(dcp->frame_id)  != DCP_FRAME_ID_GET_SET) return 0;
    if (dcp->service_id   != DCP_SVC_SET)                   return 0;
    if (dcp->service_type != DCP_SVCTYPE_RESPONSE)          return 0;
    if (DCP_NTOHL(dcp->xid) != xid)                        return 0;

    const uint8_t *p   = buf + sizeof(eth_hdr_t) + sizeof(dcp_hdr_t);
    int rem   = DCP_NTOHS(dcp->dcp_data_len);
    int avail = len - (int)(sizeof(eth_hdr_t) + sizeof(dcp_hdr_t));
    if (rem > avail) rem = avail;

    int all_ok = 1;
    while (rem >= (int)sizeof(dcp_blk_t)) {
        const dcp_blk_t *b    = (const dcp_blk_t *)p;
        uint16_t         blen = DCP_NTOHS(b->block_len);
        p   += sizeof(dcp_blk_t);
        rem -= (int)sizeof(dcp_blk_t);
        if (blen > rem) break;

        if (b->option == DCP_OPT_CONTROL && b->suboption == DCP_SUB_RESPONSE) {
            /* entries after block_info: [opt, sub, result] = 3 bytes each */
            const uint8_t *data = p + 2;
            int dlen = (int)blen - 2;
            while (dlen >= 3) {
                if (data[2] != 0) {
                    printf("    set error: opt=0x%02x sub=0x%02x result=0x%02x\n",
                           data[0], data[1], data[2]);
                    all_ok = 0;
                }
                data += 3; dlen -= 3;
            }
        }

        int adv = (int)blen + (blen & 1);
        p   += adv;
        rem -= adv;
    }

    if (all_ok) printf("    set OK\n");
    return 1;
}

static void do_set(rawsock_t *rs,
                   const uint8_t target_mac[6], const uint8_t my_mac[6],
                   const char *name_str,
                   int has_ip, const uint8_t set_ip[4],
                   const uint8_t set_mask[4], const uint8_t set_gw[4])
{
    printf("  SET -> ");
    print_mac(target_mac);
    if (name_str) printf("  name=%s", name_str);
    if (has_ip)   printf("  ip=%u.%u.%u.%u", set_ip[0],set_ip[1],set_ip[2],set_ip[3]);
    printf("\n");

    uint8_t frame[256];
    memset(frame, 0, sizeof(frame));

    eth_hdr_t *eth = (eth_hdr_t *)frame;
    dcp_hdr_t *dcp = (dcp_hdr_t *)(frame + sizeof(eth_hdr_t));

    memcpy(eth->dst, target_mac, 6);
    memcpy(eth->src, my_mac,     6);
    eth->ethertype = DCP_HTONS(ETH_P_PROFINET);

    uint32_t xid        = 0x12345678;
    dcp->frame_id       = DCP_HTONS(DCP_FRAME_ID_GET_SET);
    dcp->service_id     = DCP_SVC_SET;
    dcp->service_type   = DCP_SVCTYPE_REQUEST;
    dcp->xid            = DCP_HTONL(xid);
    dcp->response_delay = 0;

    int pos        = (int)(sizeof(eth_hdr_t) + sizeof(dcp_hdr_t));
    int data_start = pos;

    if (name_str)
        pos = dcp_append_block(frame, pos, DCP_OPT_DEVICE, DCP_SUB_DEVICE_NAME,
                               (const uint8_t *)name_str, (uint16_t)strlen(name_str));
    if (has_ip) {
        uint8_t ip_data[12];
        memcpy(ip_data,      set_ip,   4);
        memcpy(ip_data +  4, set_mask, 4);
        memcpy(ip_data +  8, set_gw,   4);
        pos = dcp_append_block(frame, pos, DCP_OPT_IP, DCP_SUB_IP_ADDR, ip_data, 12);
    }

    dcp->dcp_data_len = DCP_HTONS((uint16_t)(pos - data_start));
    if (pos < 64) pos = 64;

    if (rawsock_send(rs, frame, (size_t)pos) < 0) {
        fprintf(stderr, "    rawsock_send failed\n");
        return;
    }

    uint8_t rxbuf[2048];
    int timeout_remaining = 3000;
    for (;;) {
        int n = rawsock_recv(rs, rxbuf, sizeof(rxbuf), timeout_remaining);
        if (n == 0 || n < 0) { printf("    set timeout\n"); break; }
        if (parse_set_response(rxbuf, n, target_mac, xid)) break;
        timeout_remaining -= 10;
        if (timeout_remaining <= 0) { printf("    set timeout\n"); break; }
    }
}

/* ---------- main ---------- */

int main(int argc, char *argv[])
{
    const char *ifname     = "";
    const char *target_str = NULL;
    const char *name_str   = NULL;
    const char *ip_str     = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-t") == 0 && i + 1 < argc)
            target_str = argv[++i];
        else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc)
            name_str = argv[++i];
        else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc)
            ip_str = argv[++i];
        else
            ifname = argv[i];
    }

    uint8_t target_mac[6];
    if (target_str) {
        if (parse_mac(target_str, target_mac) < 0) {
            fprintf(stderr, "bad mac: %s\n", target_str);
            return 1;
        }
    } else {
        memcpy(target_mac, DCP_MCAST_MAC, 6);
    }

    uint8_t set_ip[4] = {0}, set_mask[4] = {0}, set_gw[4] = {0};
    if (ip_str && parse_ip_arg(ip_str, set_ip, set_mask, set_gw) < 0) {
        fprintf(stderr, "bad ip: %s  (expected ip[/mask[/gw]])\n", ip_str);
        return 1;
    }

    char error[256];
    rawsock_t *rs = rawsock_open(ifname, error, sizeof(error));
    if (!rs) { fprintf(stderr, "rawsock_open: %s\n", error); return 1; }

    uint8_t my_mac[6];
    rawsock_get_mac(rs, my_mac);

    /* --- identify phase --- */

    uint8_t frame[64];
    memset(frame, 0, sizeof(frame));

    eth_hdr_t *eth = (eth_hdr_t *)frame;
    dcp_hdr_t *dcp = (dcp_hdr_t *)(frame + sizeof(eth_hdr_t));
    dcp_blk_t *blk = (dcp_blk_t *)(frame + sizeof(eth_hdr_t) + sizeof(dcp_hdr_t));

    memcpy(eth->dst, target_mac, 6);
    memcpy(eth->src, my_mac, 6);
    eth->ethertype = DCP_HTONS(ETH_P_PROFINET);

    dcp->frame_id       = DCP_HTONS(DCP_FRAME_ID_IDENT_REQ);
    dcp->service_id     = DCP_SVC_IDENTIFY;
    dcp->service_type   = DCP_SVCTYPE_REQUEST;
    dcp->xid            = DCP_HTONL(0xDEADBEEF);
    dcp->response_delay = DCP_HTONS(1);
    dcp->dcp_data_len   = DCP_HTONS(4); /* one 4-byte all-selector block */

    blk->option    = DCP_OPT_ALL;
    blk->suboption = DCP_SUB_ALL;
    blk->block_len = DCP_HTONS(0);

    if (rawsock_send(rs, frame, sizeof(frame)) < 0) {
        fprintf(stderr, "rawsock_send failed\n");
        rawsock_close(rs);
        return 1;
    }

    printf("Sent DCP Identify All");
    if (ifname[0]) printf(" on %s", ifname);
    printf(" (src=");
    print_mac(my_mac);
    printf(")\nWaiting 3s for responses...\n\n");

    uint8_t buf[2048];
    int timeout_remaining = 3000;
    for (;;) {
        int n = rawsock_recv(rs, buf, sizeof(buf), timeout_remaining);
        if (n == 0) break;
        if (n < 0)  break;
        if (parse_ident_response(buf, n) > 0) break;
        timeout_remaining -= 10;
        if (timeout_remaining <= 0) break;
    }

    /* --- set phase (if requested) --- */

    if ((name_str || ip_str) && g_found_count > 0) {
        printf("\nSetting %d device(s)...\n", g_found_count);
        for (int i = 0; i < g_found_count; i++) {
            do_set(rs, g_found_macs[i], my_mac,
                   name_str, ip_str != NULL, set_ip, set_mask, set_gw);
        }
    } else if ((name_str || ip_str) && g_found_count == 0) {
        printf("\nNo devices found; nothing to set.\n");
    }

    printf("\nDone.\n");
    rawsock_close(rs);
    return 0;
}