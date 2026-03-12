/*
 * rawsock_macos.c - BPF raw Ethernet socket (macOS / BSD).
 *
 * Opens the first available /dev/bpfN, binds to the named interface,
 * and enables immediate mode so frames are returned without buffering delay.
 *
 * Note: BPF read() returns one or more frames packed with struct bpf_hdr
 * headers. rawsock_recv() peels off one frame per call from an internal
 * read buffer, refilling it when empty.
 */

#include "rawsock.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <net/if.h>
#include <net/bpf.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <net/if_dl.h>  /* struct sockaddr_dl */

struct rawsock_s {
    int      fd;
    uint8_t  mac[6];
    char     ifname[IF_NAMESIZE];

    /* BPF read buffer */
    uint8_t *rbuf;
    size_t   rbuf_size;
    uint8_t *rbuf_pos;   /* current read position within rbuf */
    ssize_t  rbuf_avail; /* bytes remaining from last read() */
};

rawsock_t *rawsock_open(const char *ifname, char *error, size_t errlen)
{
    rawsock_t *rs = calloc(1, sizeof(*rs));
    if (!rs) { snprintf(error, errlen, "out of memory"); return NULL; }
    strncpy(rs->ifname, ifname, IF_NAMESIZE - 1);

    /* Find a free /dev/bpfN */
    char devname[32];
    rs->fd = -1;
    for (int i = 0; i < 256; i++) {
        snprintf(devname, sizeof(devname), "/dev/bpf%d", i);
        rs->fd = open(devname, O_RDWR);
        if (rs->fd >= 0) break;
        if (errno != EBUSY) break;
    }
    if (rs->fd < 0) {
        snprintf(error, errlen, "open bpf: %s (try sudo)", strerror(errno));
        free(rs);
        return NULL;
    }

    /* Bind to interface */
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(rs->fd, BIOCSETIF, &ifr) < 0) {
        snprintf(error, errlen, "BIOCSETIF(%s): %s", ifname, strerror(errno));
        goto fail;
    }

    /* Enable immediate mode (don't wait for buffer to fill) */
    int one = 1;
    if (ioctl(rs->fd, BIOCIMMEDIATE, &one) < 0) {
        snprintf(error, errlen, "BIOCIMMEDIATE: %s", strerror(errno));
        goto fail;
    }

    /* Receive all Ethernet frames (no kernel filter) */
    if (ioctl(rs->fd, BIOCPROMISC, NULL) < 0) {
        /* Promiscuous is optional — log but don't fail */
        fprintf(stderr, "warning: BIOCPROMISC(%s): %s\n", ifname, strerror(errno));
    }

    /* Get the kernel BPF buffer size */
    u_int blen = 0;
    if (ioctl(rs->fd, BIOCGBLEN, &blen) < 0) {
        snprintf(error, errlen, "BIOCGBLEN: %s", strerror(errno));
        goto fail;
    }
    rs->rbuf_size = blen;
    rs->rbuf = malloc(blen);
    if (!rs->rbuf) {
        snprintf(error, errlen, "out of memory (bpf buf %u)", blen);
        goto fail;
    }
    rs->rbuf_avail = 0;
    rs->rbuf_pos   = rs->rbuf;

    /* Get MAC address via getifaddrs */
    struct ifaddrs *ifa_list = NULL;
    getifaddrs(&ifa_list);
    for (struct ifaddrs *ifa = ifa_list; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        if (ifa->ifa_addr->sa_family != AF_LINK) continue;
        if (strcmp(ifa->ifa_name, ifname) != 0) continue;
        struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifa->ifa_addr;
        if (sdl->sdl_alen == 6)
            memcpy(rs->mac, LLADDR(sdl), 6);
        break;
    }
    if (ifa_list) freeifaddrs(ifa_list);

    return rs;

fail:
    close(rs->fd);
    free(rs->rbuf);
    free(rs);
    return NULL;
}

void rawsock_close(rawsock_t *rs)
{
    if (!rs) return;
    close(rs->fd);
    free(rs->rbuf);
    free(rs);
}

int rawsock_send(rawsock_t *rs, const uint8_t *frame, size_t len)
{
    ssize_t n = write(rs->fd, frame, len);
    return (n < 0) ? -1 : 0;
}

int rawsock_recv(rawsock_t *rs, uint8_t *buf, size_t buflen, int timeout_ms)
{
    for (;;) {
        /* Drain frames from existing read buffer first */
        if (rs->rbuf_avail >= (ssize_t)sizeof(struct bpf_hdr)) {
            struct bpf_hdr *bh = (struct bpf_hdr *)rs->rbuf_pos;
            size_t caplen = bh->bh_caplen;
            size_t copy   = (caplen < buflen) ? caplen : buflen;
            memcpy(buf, rs->rbuf_pos + bh->bh_hdrlen, copy);

            size_t advance = BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen);
            rs->rbuf_pos   += advance;
            rs->rbuf_avail -= (ssize_t)advance;
            if (rs->rbuf_avail <= 0) {
                rs->rbuf_avail = 0;
                rs->rbuf_pos   = rs->rbuf;
            }
            return (int)copy;
        }

        /* Buffer empty — wait for more data */
        rs->rbuf_avail = 0;
        rs->rbuf_pos   = rs->rbuf;

        if (timeout_ms > 0) {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(rs->fd, &rfds);
            struct timeval tv;
            tv.tv_sec  = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;
            int r = select(rs->fd + 1, &rfds, NULL, NULL, &tv);
            if (r == 0) return 0;   /* timeout */
            if (r < 0)  return -1;
        }

        ssize_t n = read(rs->fd, rs->rbuf, rs->rbuf_size);
        if (n <= 0) return (int)n;
        rs->rbuf_avail = n;
    }
}

void rawsock_get_mac(rawsock_t *rs, uint8_t mac[6])
{
    memcpy(mac, rs->mac, 6);
}
