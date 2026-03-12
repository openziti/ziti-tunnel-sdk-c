/*
 * dcp_respond.c - Listen for PROFINET DCP Identify All broadcasts and reply
 *                 with a fake device.
 *
 * Build: see CMakeLists.txt in this directory, or for a quick Linux one-liner:
 *   gcc -o dcp_respond dcp_respond.c rawsock_linux.c
 *
 * Run:
 *   Linux/macOS : sudo ./dcp_respond eth0
 *   Windows     : dcp_respond.exe   (interface arg ignored; uses first TAP adapter)
 *
 * Edit the constants below to change the fake device's identity.
 */

#include "dcp_common.h"
#include "rawsock.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* fake device identity — edit these */
static const char    *STATION_NAME  = "fake-plc-1";
static const char    *VENDOR_NAME   = "FakeCo";
static const uint8_t  DEVICE_IP[4]   = {192, 168, 1, 200};
static const uint8_t  DEVICE_MASK[4] = {255, 255, 255,   0};
static const uint8_t  DEVICE_GW[4]   = {  0,   0,   0,   0};

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
    uint8_t txbuf[256];

    for (;;) {
        int n = rawsock_recv(rs, rxbuf, sizeof(rxbuf), 0 /* block forever */);
        if (n < (int)(sizeof(eth_hdr_t) + sizeof(dcp_hdr_t))) continue;

        const eth_hdr_t *rxeth = (const eth_hdr_t *)rxbuf;
        const dcp_hdr_t *rxdcp = (const dcp_hdr_t *)(rxbuf + sizeof(eth_hdr_t));

        if (DCP_NTOHS(rxeth->ethertype) != ETH_P_PROFINET)         continue;
        if (DCP_NTOHS(rxdcp->frame_id)  != DCP_FRAME_ID_IDENT_REQ) continue;
        if (rxdcp->service_id   != DCP_SVC_IDENTIFY)               continue;
        if (rxdcp->service_type != DCP_SVCTYPE_REQUEST)            continue;

        printf("  identify request from ");
        print_mac(rxeth->src);
        printf("  xid=0x%08x  -> responding\n", DCP_NTOHL(rxdcp->xid));

        /* Build response */
        memset(txbuf, 0, sizeof(txbuf));
        eth_hdr_t *txeth = (eth_hdr_t *)txbuf;
        dcp_hdr_t *txdcp = (dcp_hdr_t *)(txbuf + sizeof(eth_hdr_t));

        memcpy(txeth->dst, rxeth->src, 6);
        memcpy(txeth->src, my_mac,     6);
        txeth->ethertype = DCP_HTONS(ETH_P_PROFINET);

        txdcp->frame_id       = DCP_HTONS(DCP_FRAME_ID_IDENT_RSP);
        txdcp->service_id     = DCP_SVC_IDENTIFY;
        txdcp->service_type   = DCP_SVCTYPE_RESPONSE;
        txdcp->xid            = rxdcp->xid; /* already network byte order */
        txdcp->response_delay = 0;

        int pos        = (int)(sizeof(eth_hdr_t) + sizeof(dcp_hdr_t));
        int data_start = pos;

        pos = dcp_append_block(txbuf, pos, DCP_OPT_DEVICE, DCP_SUB_DEVICE_NAME,
                               (const uint8_t *)STATION_NAME, (uint16_t)strlen(STATION_NAME));
        pos = dcp_append_block(txbuf, pos, DCP_OPT_DEVICE, DCP_SUB_DEVICE_VENDOR,
                               (const uint8_t *)VENDOR_NAME,  (uint16_t)strlen(VENDOR_NAME));

        uint8_t ip_data[12];
        memcpy(ip_data,     DEVICE_IP,   4);
        memcpy(ip_data + 4, DEVICE_MASK, 4);
        memcpy(ip_data + 8, DEVICE_GW,   4);
        pos = dcp_append_block(txbuf, pos, DCP_OPT_IP, DCP_SUB_IP_ADDR, ip_data, 12);

        txdcp->dcp_data_len = DCP_HTONS((uint16_t)(pos - data_start));
        if (pos < 64) pos = 64;

        if (rawsock_send(rs, txbuf, (size_t)pos) < 0)
            fprintf(stderr, "rawsock_send failed\n");
    }

    rawsock_close(rs);
    return 0;
}
