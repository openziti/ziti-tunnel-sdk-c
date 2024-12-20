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

#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/kern_control.h>
#include <net/if.h>
#include <net/if_utun.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <sys/kern_event.h>
#include <sys/uio.h>
#include <ziti/ziti_log.h>

#include "utun.h"
#include "ziti/model_collections.h"

int utun_close(struct netif_handle_s *tun) {
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

static inline ssize_t utun_data_len(ssize_t len) {
    if (len > 0) {
        return (len > sizeof(u_int32_t)) ? len - sizeof(u_int32_t) : 0;
    } else {
        return len;
    }
}

ssize_t utun_read(netif_handle tun, void *buf, size_t len) {
    u_int32_t type;
    struct iovec iv[2];

    iv[0].iov_base = &type;
    iv[0].iov_len = sizeof(type);
    iv[1].iov_base = buf;
    iv[1].iov_len = len;

    return utun_data_len(readv(tun->fd, iv, 2));
}

ssize_t utun_write(netif_handle tun, const void *buf, size_t len) {
    u_int32_t type;
    struct iovec iv[2];
    struct ip *iph = (struct ip *)buf;

    if (iph->ip_v == 6) {
        type = htonl(AF_INET6);
    } else {
        type = htonl(AF_INET);
    }

    iv[0].iov_base = &type;
    iv[0].iov_len = sizeof(type);
    iv[1].iov_base = (void *)buf;
    iv[1].iov_len = len;

    return utun_data_len(writev(tun->fd, iv, 2));
}

int utun_uv_poll_init(netif_handle tun, uv_loop_t *loop, uv_poll_t *tun_poll_req) {
    return uv_poll_init(loop, tun_poll_req, tun->fd);
}

/**
 * this could also be done with `route` command if interface has local address assigned:
 * - ifconfig utun2 169.254.1.2/32 169.254.1.2
 * - route add -host 2.2.2.2 -interface utun2
 * - route add -host 1.2.3.4 -interface utun2
 *
 * - ifconfig utun4 inet6 2001:DB8:2:2::2/128
 * - ifconfig utun4 inet6 2001:DB8:2:2::3/128 2001:DB8:2:2::3
 */
int utun_add_route(netif_handle tun, const char *dest) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "route -n add %s -interface %s", dest, tun->name);
    int s = system(cmd);
    return s;
}

int utun_delete_route(netif_handle tun, const char *dest) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "route -n delete %s -interface %s", dest, tun->name);
    int s = system(cmd);
    return s;
}

static model_map excluded;
static uv_once_t delete_once;

static void delete_excluded() {
    char cmd[1024];
    const char *rt;
    void *dummy;
    MODEL_MAP_FOREACH(rt, dummy, &excluded) {
        snprintf(cmd, sizeof(cmd), "route -q -n delete %s", rt);
        system(cmd);
    }
    model_map_clear(&excluded, free);
}
static void delete_init() {
    int rc = atexit(delete_excluded);
    if (rc) {
        ZITI_LOG(WARN, "failed to register route cleanup: %s", strerror(errno));
    }
}

static int utun_exclude_rt(netif_handle dev, uv_loop_t *l, const char *addr) {
    uv_once(&delete_once, delete_init);

    char gw[128] = {0};
    const char *get_gw_cmd = "route -n get default | awk '/gateway: / { printf \"%s\", $2 }'";
    ZITI_LOG(DEBUG, "executing '%s'", get_gw_cmd);
    FILE *get_gw_pipe = popen(get_gw_cmd, "r");
    if (get_gw_pipe == NULL) {
        ZITI_LOG(ERROR, "popen(%s) failed", get_gw_cmd);
        return -1;
    }
    size_t gw_len = fread(gw, 1, sizeof(gw), get_gw_pipe);
    int s = pclose(get_gw_pipe);
    if (!WIFEXITED(s) || WEXITSTATUS(s) != 0) {
        ZITI_LOG(ERROR, "%s failed", get_gw_cmd);
        return -1;
    }
    if (ferror(get_gw_pipe) || gw_len == 0) {
        ZITI_LOG(ERROR, "failed to get default gateway");
        return -1;
    }
    ZITI_LOG(DEBUG, "default route gw is '%s'", gw);

    model_map_set(&excluded, addr, NULL);

    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "route -n add %s %s", addr, gw);
    ZITI_LOG(DEBUG, "executing '%s'", cmd);
    s = system(cmd);
    return s;
}

static const char *get_tun_name(netif_handle tun) {
    return tun->name;
}

/**
 * open a utun device
 * @param num populated with the unit number of the utun device that was opened
 * @return file descriptor to opened utun
 */
netif_driver utun_open(char *error, size_t error_len, const char *cidr) {
    if (error != NULL) {
        memset(error, 0, error_len * sizeof(char));
    }

    struct netif_handle_s *tun = calloc(1, sizeof(struct netif_handle_s));
    if (tun == NULL) {
        if (error != NULL) {
            snprintf(error, error_len, "failed to allocate utun");
        }
        return NULL;
    }

    struct sockaddr_ctl addr;

    if ((tun->fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)) < 0) {
        if (error != NULL) {
            snprintf(error, error_len, "failed to create control socket: %s", strerror(errno));
        }
        utun_close(tun);
        return NULL;
    }

    struct ctl_info info;
    memset(&info, 0, sizeof (info));
    strncpy(info.ctl_name, UTUN_CONTROL_NAME, strlen(UTUN_CONTROL_NAME));
    if (ioctl(tun->fd, CTLIOCGINFO, &info) == -1) {
        if (error != NULL) {
            snprintf(error, error_len, "ioctl(CTLIOCGINFO) failed: %s", strerror(errno));
        }
        utun_close(tun);
        return NULL;
    }

    addr.sc_id = info.ctl_id;
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    addr.sc_unit = 0; // use first available unit

    if (connect(tun->fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        if (error != NULL) {
            snprintf(error, error_len, "failed to open utun device: %s", strerror(errno));
        }
        utun_close(tun);
        return NULL;
    }

    struct ifreq if_req;
    socklen_t ifname_req_size = sizeof(if_req);
    if (getsockopt(tun->fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, &if_req, &ifname_req_size) == -1) {
        if (error != NULL) {
            snprintf(error, error_len, "failed to get ifname: %s", strerror(errno));
        }
        utun_close(tun);
        return NULL;
    }
    strncpy(tun->name, if_req.ifr_name, sizeof(tun->name));

    int s = socket(PF_LOCAL, SOCK_DGRAM, 0);
    if (s < 0) {
        if (error != NULL) {
            snprintf(error, error_len, "failed to get socket: %s", strerror(errno));
        }
        return NULL;
    }

    if_req.ifr_mtu = 0xFFFF;
    if (ioctl(s, SIOCSIFMTU, &if_req) == -1) {
        if (error != NULL) {
            snprintf(error, error_len, "failed to get mtu: %s", strerror(errno));
        }
        utun_close(tun);
        return NULL;
    }

    struct netif_driver_s *driver = calloc(1, sizeof(struct netif_driver_s));
    if (driver == NULL) {
        if (error != NULL) {
            snprintf(error, error_len, "failed to allocate netif_device_s");
            utun_close(tun);
        }
        return NULL;
    }

    driver->handle       = tun;
    driver->read         = utun_read;
    driver->write        = utun_write;
    driver->uv_poll_init = utun_uv_poll_init;
    driver->add_route    = utun_add_route;
    driver->delete_route = utun_delete_route;
    driver->exclude_rt   = utun_exclude_rt;
    driver->close        = utun_close;
    driver->get_name = get_tun_name;

    if (cidr) {
        char cmd[1024];
        int ip_len = (int)strlen(cidr);
        const char *prefix_sep = strchr(cidr, '/');
        if (prefix_sep != NULL) {
            ip_len = (int)(prefix_sep - cidr);
        }
        // add address to interface. darwin utun devices may only have "point to point" addresses
        snprintf(cmd, sizeof(cmd), "ifconfig %s %.*s %.*s netmask 255.255.255.255", tun->name, ip_len, cidr, ip_len, cidr);
        system(cmd);

        // add a route for the subnet if one was specified
        if (prefix_sep != NULL) {
            snprintf(cmd, sizeof(cmd), "route -n add -net %s -interface %s", cidr, tun->name);
            system(cmd);
        }
    }
    return driver;
}