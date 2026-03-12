/*
 * rawsock_linux.c - AF_PACKET raw Ethernet socket (Linux).
 */

#include "rawsock.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

struct rawsock_s {
    int     fd;
    int     ifindex;
    uint8_t mac[6];
};

rawsock_t *rawsock_open(const char *ifname, char *error, size_t errlen)
{
    rawsock_t *rs = calloc(1, sizeof(*rs));
    if (!rs) { snprintf(error, errlen, "out of memory"); return NULL; }

    rs->fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (rs->fd < 0) {
        snprintf(error, errlen, "socket: %s", strerror(errno));
        free(rs);
        return NULL;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(rs->fd, SIOCGIFINDEX, &ifr) < 0) {
        snprintf(error, errlen, "SIOCGIFINDEX(%s): %s", ifname, strerror(errno));
        goto fail;
    }
    rs->ifindex = ifr.ifr_ifindex;

    if (ioctl(rs->fd, SIOCGIFHWADDR, &ifr) < 0) {
        snprintf(error, errlen, "SIOCGIFHWADDR(%s): %s", ifname, strerror(errno));
        goto fail;
    }
    memcpy(rs->mac, ifr.ifr_hwaddr.sa_data, 6);

    struct sockaddr_ll sll = {0};
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = rs->ifindex;
    if (bind(rs->fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        snprintf(error, errlen, "bind(%s): %s", ifname, strerror(errno));
        goto fail;
    }

    return rs;

fail:
    close(rs->fd);
    free(rs);
    return NULL;
}

void rawsock_close(rawsock_t *rs)
{
    if (!rs) return;
    close(rs->fd);
    free(rs);
}

int rawsock_send(rawsock_t *rs, const uint8_t *frame, size_t len)
{
    struct sockaddr_ll dst = {0};
    dst.sll_family  = AF_PACKET;
    dst.sll_ifindex = rs->ifindex;
    dst.sll_halen   = 6;
    memcpy(dst.sll_addr, frame, 6); /* dst MAC is first 6 bytes of frame */

    ssize_t n = sendto(rs->fd, frame, len, 0,
                       (struct sockaddr *)&dst, sizeof(dst));
    return (n < 0) ? -1 : 0;
}

int rawsock_recv(rawsock_t *rs, uint8_t *buf, size_t buflen, int timeout_ms)
{
    if (timeout_ms > 0) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(rs->fd, &rfds);
        struct timeval tv;
        tv.tv_sec  = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        int r = select(rs->fd + 1, &rfds, NULL, NULL, &tv);
        if (r == 0) return 0;  /* timeout */
        if (r < 0)  return -1;
    }

    ssize_t n = recv(rs->fd, buf, buflen, 0);
    return (int)n;
}

void rawsock_get_mac(rawsock_t *rs, uint8_t mac[6])
{
    memcpy(mac, rs->mac, 6);
}
