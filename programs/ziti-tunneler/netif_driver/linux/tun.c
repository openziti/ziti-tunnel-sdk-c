#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>


#ifndef DEVTUN
#define DEVTUN "/dev/net/tun"
#endif

#define IP_ADDR_ARGS "addr add %d.%d.%d.%d/24 dev %s"
#define IP_UP_ARGS "link set %s up"
#define IP_BIN "/sbin/ip "

int tun_create(char *dev) {
    int fd = -1;

    struct ifreq ifr;

    if ((fd = open(DEVTUN, O_RDWR)) < 0) {
        printf("open %s failed\n", DEVTUN);
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if (ioctl(fd, TUNSETIFF, (void *) &ifr) < 0) {
        printf("failed to open tun device\n");
        close(fd);
        return -1;
    }
    strcpy(dev, ifr.ifr_name);

    printf("Open tun device: %s for reading...\n", ifr.ifr_name);

    return fd;
}