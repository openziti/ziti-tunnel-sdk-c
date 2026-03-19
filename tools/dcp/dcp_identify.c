/*
 * dcp_identify.c - Send a PROFINET DCP Identify All broadcast and print responses.
 *
 * Build: see CMakeLists.txt in this directory, or for a quick Linux one-liner:
 *   gcc -o dcp_identify dcp_identify.c rawsock_linux.c
 *
 * Run:
 *   Linux/macOS : sudo ./dcp_identify eth0
 *   Windows     : dcp_identify.exe   (interface arg ignored; uses first TAP adapter)
 */

#include "dcp_common.h"
#include "rawsock.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void parse_response(const uint8_t *buf, int len)
{
    if (len < (int)(sizeof(eth_hdr_t) + sizeof(dcp_hdr_t))) return;

    const eth_hdr_t *eth = (const eth_hdr_t *)buf;
    const dcp_hdr_t *dcp = (const dcp_hdr_t *)(buf + sizeof(eth_hdr_t));

    if (DCP_NTOHS(eth->ethertype) != ETH_P_PROFINET)         return;
    if (DCP_NTOHS(dcp->frame_id)  != DCP_FRAME_ID_IDENT_RSP) return;
    if (dcp->service_id != DCP_SVC_IDENTIFY)                  return;
    if (dcp->service_type != DCP_SVCTYPE_RESPONSE)            return;

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
}

static int parse_mac(const char *s, uint8_t mac[6])
{
    unsigned v[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x", &v[0],&v[1],&v[2],&v[3],&v[4],&v[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++) mac[i] = (uint8_t)v[i];
    return 0;
}

int main(int argc, char *argv[])
{
    /* Usage: dcp_identify [ifname] [-t target-mac] */
    const char *ifname     = "";
    const char *target_str = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-t") == 0 && i + 1 < argc)
            target_str = argv[++i];
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

    char error[256];
    rawsock_t *rs = rawsock_open(ifname, error, sizeof(error));
    if (!rs) { fprintf(stderr, "rawsock_open: %s\n", error); return 1; }

    uint8_t my_mac[6];
    rawsock_get_mac(rs, my_mac);

    /* Build DCP Identify All frame */
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
    int timeout_remaining = 3000; /* 3 seconds total */
    for (;;) {
        int n = rawsock_recv(rs, buf, sizeof(buf), timeout_remaining);
        if (n == 0) break;  /* timeout */
        if (n < 0)  break;  /* error */
        parse_response(buf, n);
        /* Reduce remaining timeout by a tick — good enough for a test tool */
        timeout_remaining -= 10;
        if (timeout_remaining <= 0) break;
    }

    printf("\nDone.\n");
    rawsock_close(rs);
    return 0;
}
