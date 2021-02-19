#include <sys/ioctl.h>
//#include <linux/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>

#include "tun.h"

#ifndef DEVTUN
#define DEVTUN "/dev/net/tun"
#endif

/*
 * ip link set tun0 up
 * ip addr add 169.254.1.1 remote 169.254.0.0/16 dev tun0
 */

#if 0
#define IP_ADDR_ARGS "addr add %d.%d.%d.%d/24 dev %s"
#define IP_UP_ARGS "link set %s up"
#define IP_BIN "/sbin/ip "
#endif

#define RESOLVECTL "resolvectl"

static int tun_close(struct netif_handle_s *tun) {
    int r = 0;

    if (tun == NULL) {
        return 0;
    }

    if (tun->fd > 0) {
        r = close(tun->fd);
    }

    free(tun);
    return r;
}

ssize_t tun_read(netif_handle tun, void *buf, size_t len) {
    return read(tun->fd, buf, len);
}

ssize_t tun_write(netif_handle tun, const void *buf, size_t len) {
    return write(tun->fd, buf, len);
}

int tun_uv_poll_init(netif_handle tun, uv_loop_t *loop, uv_poll_t *tun_poll_req) {
    return uv_poll_init(loop, tun_poll_req, tun->fd);
}

int tun_add_route(netif_handle tun, const char *dest) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "ip route add %s dev %s", dest, tun->name);
    int s = system(cmd);
    return s;
}

int tun_delete_route(netif_handle tun, const char *dest) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "ip route delete %s dev %s", dest, tun->name);
    int s = system(cmd);
    return s;
}

static void run_command(const char* cmd, ...) {
    char cmdline[1024];
    va_list args;
    va_start(args, cmd);

    vsprintf(cmdline, cmd, args);

    int rc = system(cmdline);
    if (rc != 0) {
        fprintf(stderr, "cmd{%s} failed: %d/%d/%s\n", cmd, rc, errno, strerror(errno));
    }
}

netif_driver tun_open(uint32_t tun_ip, uint32_t dns_ip, const char *dns_block, char *error, size_t error_len) {
    if (error != NULL) {
        memset(error, 0, error_len * sizeof(char));
    }

    struct netif_handle_s *tun = calloc(1, sizeof(struct netif_handle_s));
    if (tun == NULL) {
        if (error != NULL) {
            snprintf(error, error_len, "failed to allocate tun");
        }
        return NULL;
    }

    if ((tun->fd = open(DEVTUN, O_RDWR)) < 0) {
        if (error != NULL) {
            snprintf(error, error_len,"open %s failed", DEVTUN);
        }
        free(tun);
        return NULL;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if (ioctl(tun->fd, TUNSETIFF, (void *) &ifr) < 0) {
        if (error != NULL) {
            snprintf(error, error_len, "failed to open tun device:%s", strerror(errno));
        }
        tun_close(tun);
        return NULL;
    }

    strncpy(tun->name, ifr.ifr_name, sizeof(tun->name));

    struct netif_driver_s *driver = calloc(1, sizeof(struct netif_driver_s));
    if (driver == NULL) {
        if (error != NULL) {
            snprintf(error, error_len, "failed to allocate netif_device_s");
            tun_close(tun);
        }
        return NULL;
    }

    driver->handle       = tun;
    driver->read         = tun_read;
    driver->write        = tun_write;
    driver->uv_poll_init = tun_uv_poll_init;
    driver->add_route    = tun_add_route;
    driver->delete_route = tun_delete_route;
    driver->close        = tun_close;

    run_command("ip link set %s up", tun->name);
    run_command("ip addr add %s dev %s", inet_ntoa(*(struct in_addr*)&tun_ip), tun->name);

    if (dns_ip) {
        run_command(RESOLVECTL " dns %s %s", tun->name, inet_ntoa(*(struct in_addr*)&dns_ip));
        run_command(RESOLVECTL " domain %s ~.", tun->name);
    }

    if (dns_block) {
        run_command("ip route add %s dev %s", dns_block, tun->name);
    }

    return driver;
}