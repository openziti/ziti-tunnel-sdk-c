//#include <sys/uio.h>

#include "uv.h"
#include "lwip/err.h"
#include "lwip/pbuf.h"
#include "lwip/ip_addr.h"
#include "lwip/netif.h"
#include "lwip/etharp.h"
#include "lwip/ethip6.h"
#include "ziti/netif_driver.h"
#include "netif_shim.h"
#include "../ziti_tunnel_priv.h"

#define IFNAME0 't'
#define IFNAME1 'n'

/* max ipv4 MTU */
#define BUFFER_SIZE 64 * 1024

static char shim_buffer[BUFFER_SIZE];
/**
 * This function is called by the TCP/IP stack when an IP packet should be sent.
 */
static err_t netif_shim_output(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr) {
    netif_driver dev = netif->state;

    u16_t copied = pbuf_copy_partial(p, shim_buffer, p->tot_len, 0);
    if (copied != p->tot_len) {
        TNL_LOG(ERR, "pbuf_copy_partial() failed %d/%d", copied, p->tot_len);
        return ERR_BUF; // ?
    }

    if (ip_ver(shim_buffer) == 4)
        TNL_LOG(TRACE, "writing packet " PACKET_FMT " len=%d", PACKET_FMT_ARGS(shim_buffer), copied);
    dev->write(dev->handle, shim_buffer, p->tot_len);
    return ERR_OK;
}

/**
 * This function is called by the TCP/IP stack when an IP6 packet should be sent.
 */
static err_t netif_shim_output_ip6(struct netif *netif, struct pbuf *p, const ip6_addr_t *ipaddr) {
    return netif_shim_output(netif, p, NULL);
}

static err_t netif_shim_output_link(struct netif *netif, struct pbuf *p) {
    return netif_shim_output(netif, p, NULL);
}

/**
 * This function should be called when a packet is ready to be read
 * from the interface. It uses the function low_level_input() that
 * should handle the actual reception of bytes from the network
 * interface.
 */
void netif_shim_input(struct netif *netif) {
    netif_driver dev = netif->state;
    char buf[BUFFER_SIZE];

    int count = 0;
    while (count < 128) {
        ssize_t nr = dev->read(dev->handle, buf, sizeof(buf));
        if ((nr <= 0) || (nr > 0xffff)) {
            break;
        }
        count++;

        if (ip_ver(buf) == 4)
            TNL_LOG(TRACE, "received packet " PACKET_FMT " len=%zd", PACKET_FMT_ARGS(buf), nr);

        on_packet(buf, nr, netif);
    }
    TNL_LOG(TRACE, "done after reading %d packets", count);
}

#include <netif/ethernet.h>
void on_packet(const char *buf, ssize_t nr, void *ctx) {
    static bool log_pbuf_errors = true;
    struct netif *netif = ctx;
    struct pbuf *p;
    /* We allocate a pbuf chain of pbufs from the pool. */
    p = pbuf_alloc(PBUF_RAW, (u16_t) nr, PBUF_POOL);

    if (p != NULL) {
        if (!log_pbuf_errors) {
            TNL_LOG(INFO, "pbufs are now available. packets will no longer be dropped");
            log_pbuf_errors = true;
        }
        err_t e = pbuf_take(p, buf, (u16_t) nr);
        if (e != ERR_OK) {
            TNL_LOG(ERR, "pbuf_take failed: %d", e);
            pbuf_free(p);
            return;
        }
        /* acknowledge that packet has been read(); */
    } else {
        /* drop packet(); */
        if (log_pbuf_errors) {
            TNL_LOG(ERR, "pbuf_alloc failed. dropping packets until pbufs become available");
            log_pbuf_errors = false;
        }
        return;
    }

    err_t err = netif->input(p, netif);
    if (err != ERR_OK) {
        TNL_LOG(ERR, "============================> tunif_input: netif input error %s", lwip_strerr(err));
        pbuf_free(p);
    }
}

/**
 * Should be called at the beginning of the program to set up the
 * network interface. It calls the function low_level_init() to do the
 * actual setup of the hardware.
 */
err_t netif_shim_init(struct netif *netif) {
    netif->name[0] = IFNAME0;
    netif->name[1] = IFNAME1;
    netif->output = netif_shim_output;
    netif->output_ip6 = netif_shim_output_ip6;

    /* todo this isn't working for ip packets. packets are received but we can't send because `etharp_output`
     *  wants to see arp answers for IPs that we intercept. I'm guessuming something isn't quite right with
     *  the addresses here but will get back to it after plain l2 service is working. for now the tunneler
     *  will not handle l3 services when the l2 option is used.
     */
    netif_driver dev = netif->state;
    netif->ip_addr.type = IPADDR_TYPE_V4;
    netif->ip_addr.u_addr.ip4.addr = dev->ip4addr.s_addr;
    netif->netmask.type = IPADDR_TYPE_V4;
    netif->netmask.u_addr.ip4.addr = 4294967295; // todo set this (and gw?) for real
    netif->mtu = dev->mtu;
    if (dev->hwaddr_len != 0) {
        netif->output = etharp_output;
        netif->output_ip6 = ethip6_output;
        memcpy(netif->hwaddr, dev->hwaddr, dev->hwaddr_len);
        netif->hwaddr_len = dev->hwaddr_len;
        // todo do we need to call netif_create_ip6_linklocal_address?
        netif->linkoutput = netif_shim_output_link;
    }

    return ERR_OK;
}