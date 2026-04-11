/*
 * dcp_respond.c - Listen for PROFINET DCP Identify All broadcasts and reply
 *                 with a fake device.  Also handles DCP SET requests to update
 *                 the device's station name and/or IP configuration at runtime.
 *
 * Build: see CMakeLists.txt in this directory, or for a quick Linux one-liner:
 *   gcc -o dcp_respond dcp_respond.c rawsock_linux.c
 *
 * Run:
 *   Linux/macOS : sudo ./dcp_respond eth0
 *   Windows     : dcp_respond.exe   (interface arg ignored; uses first TAP adapter)
 *
 * Edit the constants below to change the fake device's initial identity.
 */

#include "dcp_common.h"
#include "rawsock.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* fake device identity — mutable so DCP SET can update them at runtime */
static char    STATION_NAME[256] = "fake-plc-1";
static char    VENDOR_NAME[256]  = "FakeCo";
static uint8_t DEVICE_IP[4]      = {192, 168, 1, 200};
static uint8_t DEVICE_MASK[4]    = {255, 255, 255,   0};
static uint8_t DEVICE_GW[4]      = {  0,   0,   0,   0};

static void handle_identify(rawsock_t *rs,
                             const uint8_t *rxbuf, int rxlen,
                             const uint8_t my_mac[6])
{
    (void)rxlen;
    const eth_hdr_t *rxeth = (const eth_hdr_t *)rxbuf;
    const dcp_hdr_t *rxdcp = (const dcp_hdr_t *)(rxbuf + sizeof(eth_hdr_t));

    printf("  identify request from ");
    print_mac(rxeth->src);
    printf("  xid=0x%08x  -> responding\n", DCP_NTOHL(rxdcp->xid));

    uint8_t txbuf[256];
    memset(txbuf, 0, sizeof(txbuf));
    eth_hdr_t *txeth = (eth_hdr_t *)txbuf;
    dcp_hdr_t *txdcp = (dcp_hdr_t *)(txbuf + sizeof(eth_hdr_t));

    memcpy(txeth->dst, rxeth->src, 6);
    memcpy(txeth->src, my_mac,     6);
    txeth->ethertype = DCP_HTONS(ETH_P_PROFINET);

    txdcp->frame_id       = DCP_HTONS(DCP_FRAME_ID_IDENT_RSP);
    txdcp->service_id     = DCP_SVC_IDENTIFY;
    txdcp->service_type   = DCP_SVCTYPE_RESPONSE;
    txdcp->xid            = rxdcp->xid;
    txdcp->response_delay = 0;

    int pos        = (int)(sizeof(eth_hdr_t) + sizeof(dcp_hdr_t));
    int data_start = pos;

    pos = dcp_append_block(txbuf, pos, DCP_OPT_DEVICE, DCP_SUB_DEVICE_NAME,
                           (const uint8_t *)STATION_NAME, (uint16_t)strlen(STATION_NAME));
    pos = dcp_append_block(txbuf, pos, DCP_OPT_DEVICE, DCP_SUB_DEVICE_VENDOR,
                           (const uint8_t *)VENDOR_NAME,  (uint16_t)strlen(VENDOR_NAME));

    uint8_t ip_data[12];
    memcpy(ip_data,      DEVICE_IP,   4);
    memcpy(ip_data +  4, DEVICE_MASK, 4);
    memcpy(ip_data +  8, DEVICE_GW,   4);
    pos = dcp_append_block(txbuf, pos, DCP_OPT_IP, DCP_SUB_IP_ADDR, ip_data, 12);

    txdcp->dcp_data_len = DCP_HTONS((uint16_t)(pos - data_start));
    if (pos < 64) pos = 64;

    if (rawsock_send(rs, txbuf, (size_t)pos) < 0)
        fprintf(stderr, "rawsock_send failed\n");
}

static void handle_set(rawsock_t *rs,
                        const uint8_t *rxbuf, int rxlen,
                        const uint8_t my_mac[6])
{
    const eth_hdr_t *rxeth = (const eth_hdr_t *)rxbuf;
    const dcp_hdr_t *rxdcp = (const dcp_hdr_t *)(rxbuf + sizeof(eth_hdr_t));

    printf("  set request from ");
    print_mac(rxeth->src);
    printf("  xid=0x%08x\n", DCP_NTOHL(rxdcp->xid));

    const uint8_t *p   = rxbuf + sizeof(eth_hdr_t) + sizeof(dcp_hdr_t);
    int rem   = DCP_NTOHS(rxdcp->dcp_data_len);
    int avail = rxlen - (int)(sizeof(eth_hdr_t) + sizeof(dcp_hdr_t));
    if (rem > avail) rem = avail;

    /* Collect per-block results for the Control/Response: [opt, sub, result] triples */
    uint8_t resp_entries[64];
    int     resp_len = 0;

    while (rem >= (int)sizeof(dcp_blk_t)) {
        const dcp_blk_t *b    = (const dcp_blk_t *)p;
        uint16_t         blen = DCP_NTOHS(b->block_len);
        p   += sizeof(dcp_blk_t);
        rem -= (int)sizeof(dcp_blk_t);
        if (blen > rem) break;

        /* p now points to block_info (2 bytes); payload starts at p+2 */
        uint8_t result = 0x00; /* success */

        if (b->option == DCP_OPT_DEVICE && b->suboption == DCP_SUB_DEVICE_NAME && blen > 2) {
            int nlen = (int)blen - 2;
            if (nlen >= (int)sizeof(STATION_NAME))
                nlen = (int)sizeof(STATION_NAME) - 1;
            memcpy(STATION_NAME, p + 2, (size_t)nlen);
            STATION_NAME[nlen] = '\0';
            printf("    station-name -> %s\n", STATION_NAME);
        } else if (b->option == DCP_OPT_IP && b->suboption == DCP_SUB_IP_ADDR && blen >= 14) {
            memcpy(DEVICE_IP,   p + 2,  4);
            memcpy(DEVICE_MASK, p + 6,  4);
            memcpy(DEVICE_GW,   p + 10, 4);
            printf("    ip/mask/gw   -> %u.%u.%u.%u / %u.%u.%u.%u / %u.%u.%u.%u\n",
                   DEVICE_IP[0],   DEVICE_IP[1],   DEVICE_IP[2],   DEVICE_IP[3],
                   DEVICE_MASK[0], DEVICE_MASK[1], DEVICE_MASK[2], DEVICE_MASK[3],
                   DEVICE_GW[0],   DEVICE_GW[1],   DEVICE_GW[2],   DEVICE_GW[3]);
        } else {
            result = 0x01; /* option not supported */
        }

        if (resp_len + 3 <= (int)sizeof(resp_entries)) {
            resp_entries[resp_len++] = b->option;
            resp_entries[resp_len++] = b->suboption;
            resp_entries[resp_len++] = result;
        }

        int adv = (int)blen + (blen & 1);
        p   += adv;
        rem -= adv;
    }

    /* Build and send Control/Response */
    uint8_t txbuf[256];
    memset(txbuf, 0, sizeof(txbuf));
    eth_hdr_t *txeth = (eth_hdr_t *)txbuf;
    dcp_hdr_t *txdcp = (dcp_hdr_t *)(txbuf + sizeof(eth_hdr_t));

    memcpy(txeth->dst, rxeth->src, 6);
    memcpy(txeth->src, my_mac,     6);
    txeth->ethertype = DCP_HTONS(ETH_P_PROFINET);

    txdcp->frame_id       = DCP_HTONS(DCP_FRAME_ID_GET_SET);
    txdcp->service_id     = DCP_SVC_SET;
    txdcp->service_type   = DCP_SVCTYPE_RESPONSE;
    txdcp->xid            = rxdcp->xid;
    txdcp->response_delay = 0;

    int pos        = (int)(sizeof(eth_hdr_t) + sizeof(dcp_hdr_t));
    int data_start = pos;

    pos = dcp_append_block(txbuf, pos, DCP_OPT_CONTROL, DCP_SUB_RESPONSE,
                           resp_entries, (uint16_t)resp_len);

    txdcp->dcp_data_len = DCP_HTONS((uint16_t)(pos - data_start));
    if (pos < 64) pos = 64;

    if (rawsock_send(rs, txbuf, (size_t)pos) < 0)
        fprintf(stderr, "rawsock_send failed\n");
}

int main(int argc, char *argv[])
{
    const char *ifname = (argc >= 2) ? argv[1] : "";

    char error[256];
    rawsock_t *rs = rawsock_open(ifname, error, sizeof(error));
    if (!rs) { fprintf(stderr, "rawsock_open: %s\n", error); return 1; }

    uint8_t my_mac[6];
    rawsock_get_mac(rs, my_mac);

    printf("Listening");
    if (ifname[0]) printf(" on %s", ifname);
    printf(" (mac=");
    print_mac(my_mac);
    printf(")\n  station-name : %s\n  vendor       : %s\n  ip           : %u.%u.%u.%u\n\n",
           STATION_NAME, VENDOR_NAME,
           DEVICE_IP[0], DEVICE_IP[1], DEVICE_IP[2], DEVICE_IP[3]);

    uint8_t rxbuf[2048];
    for (;;) {
        int n = rawsock_recv(rs, rxbuf, sizeof(rxbuf), 0 /* block forever */);
        if (n < (int)(sizeof(eth_hdr_t) + sizeof(dcp_hdr_t))) continue;

        const eth_hdr_t *rxeth = (const eth_hdr_t *)rxbuf;
        const dcp_hdr_t *rxdcp = (const dcp_hdr_t *)(rxbuf + sizeof(eth_hdr_t));

        if (DCP_NTOHS(rxeth->ethertype) != ETH_P_PROFINET) continue;

        uint16_t frame_id = DCP_NTOHS(rxdcp->frame_id);

        if (frame_id == DCP_FRAME_ID_IDENT_REQ
            && rxdcp->service_id   == DCP_SVC_IDENTIFY
            && rxdcp->service_type == DCP_SVCTYPE_REQUEST)
        {
            handle_identify(rs, rxbuf, n, my_mac);
        }
        else if (frame_id == DCP_FRAME_ID_GET_SET
                 && rxdcp->service_id   == DCP_SVC_SET
                 && rxdcp->service_type == DCP_SVCTYPE_REQUEST)
        {
            handle_set(rs, rxbuf, n, my_mac);
        }
    }

    rawsock_close(rs);
    return 0;
}