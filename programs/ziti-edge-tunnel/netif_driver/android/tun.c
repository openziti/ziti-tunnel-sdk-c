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

/*
 * TUN driver for Android. Android's userspace never gets systemd-resolved,
 * NetworkManager, or nftables/iptables-in-the-usual-sense, and its kernel
 * routes through per-UID policy routing tables ahead of the main table, so
 * this driver intentionally diverges from netif_driver/linux/tun.c rather
 * than sharing it via #ifdef:
 *
 *   - no DNS maintainer: there is no systemd-resolved/resolvconf to steer,
 *     so route resolution is left entirely to the identity's intercept
 *     config.
 *   - route updates add a policy routing rule (pref 12000) that forces
 *     ziti-intercepted destinations to consult the main table, where the
 *     tun route lives, ahead of Android's own per-app routing tables.
 *   - tun_open grants the tun interface an explicit iptables INPUT/OUTPUT
 *     ACCEPT, since stock FireOS firewalls default those chains to DROP
 *     and only allow-lists wlan0/lo.
 */

#include <sys/ioctl.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/if_tun.h>

#include <ziti/ziti_log.h>

#include "tun.h"
#include "../linux/utils.h"

#define DEVTUN "/dev/tun"

static int tun_close(struct netif_handle_s *tun) {
    int r = 0;

    if (tun == NULL) {
        return 0;
    }

    if (tun->name[0] != '\0') {
        while (run_command("iptables -D OUTPUT -o %s -j ACCEPT >/dev/null 2>&1", tun->name) == 0) {}
        while (run_command("iptables -D INPUT -i %s -j ACCEPT >/dev/null 2>&1", tun->name) == 0) {}
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
    if (tun->route_updates == NULL) {
        tun->route_updates = calloc(1, sizeof(*tun->route_updates));
    }
    model_map_set(tun->route_updates, dest, (void*)(uintptr_t)true);
    return 0;
}

int tun_delete_route(netif_handle tun, const char *dest) {
    if (tun->route_updates == NULL) {
        tun->route_updates = calloc(1, sizeof(*tun->route_updates));
    }
    model_map_set(tun->route_updates, dest, (void*)(uintptr_t)false);
    return 0;
}

struct rt_process_cmd {
    model_map *updates;
    netif_handle tun;
};

static void route_updates_done(uv_work_t *wr, int status) {
    struct rt_process_cmd *cmd = wr->data;
    ZITI_LOG(INFO, "route updates[%zd]: %d/%s", model_map_size(cmd->updates), status, status ? uv_strerror(status) : "OK");

    model_map_iter it = model_map_iterator(cmd->updates);
    while(it) {
        it = model_map_it_remove(it);
    }
    free(cmd->updates);
    free(cmd);
    free(wr);
}

static void process_routes_updates(uv_work_t *wr) {
    struct rt_process_cmd *cmd = wr->data;
    const char *prefix;
    const void *value;

    MODEL_MAP_FOREACH(prefix, value, cmd->updates) {
        unsigned action = (uintptr_t)value;

        if (action) {
            ZITI_LOG(INFO, "Android adding route %s via %s", prefix, cmd->tun->name);

            run_command("ip route add %s dev %s", prefix, cmd->tun->name);

            /*
             * Android uses policy routing tables before the main table.
             * Add a high priority rule forcing Ziti intercept destinations
             * to consult the main table where the ziti0 route exists.
             */
            run_command("ip rule add pref 12000 to %s lookup main", prefix);
        } else {
            ZITI_LOG(INFO, "Android deleting route %s via %s", prefix, cmd->tun->name);

            run_command("ip route delete %s dev %s", prefix, cmd->tun->name);
            run_command("ip rule del pref 12000 to %s lookup main", prefix);
        }
    }
}

int tun_commit_routes(netif_handle tun, uv_loop_t *l) {
    uv_work_t *wr = calloc(1, sizeof(uv_work_t));
    struct rt_process_cmd *cmd = calloc(1, sizeof(struct rt_process_cmd));
    if (tun->route_updates && model_map_size(tun->route_updates) > 0) {
        ZITI_LOG(INFO, "starting %zd route updates", model_map_size(tun->route_updates));
        cmd->tun = tun;
        cmd->updates = tun->route_updates;
        wr->data = cmd;
        tun->route_updates = NULL;
        uv_queue_work(l, wr, process_routes_updates, route_updates_done);
    }
    return 0;
}

static int tun_exclude_rt(netif_handle dev, uv_loop_t *l, const char *addr) {
    /*
     * The pref-12000 rule installed in process_routes_updates() already
     * forces every ziti-intercepted destination through the main table,
     * so there is no separate "excluded route" table to maintain here.
     */
    (void)dev;
    (void)l;
    (void)addr;
    return 0;
}

static void cleanup_sock(const int *fd) {
    if (fd && *fd != -1) {
        close(*fd);
    }
}

static const char *get_tun_name(netif_handle tun) {
    return tun->name;
}

netif_driver tun_open(uv_loop_t *loop, uint32_t tun_ip, uint32_t dns_ip, const char *dns_block, char *error, size_t error_len) {
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

    if ((tun->fd = open(DEVTUN, O_RDWR|O_CLOEXEC)) < 0) {
        if (error != NULL) {
            snprintf(error, error_len,"open %s failed", DEVTUN);
        }
        free(tun);
        return NULL;
    }

    struct ifreq ifr = { .ifr_name = "ziti%d", .ifr_flags = IFF_TUN | IFF_NO_PI };

    if (ioctl(tun->fd, TUNSETIFF, &ifr) < 0) {
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
        }
        tun_close(tun);
        return NULL;
    }

    driver->handle        = tun;
    driver->read          = tun_read;
    driver->write         = tun_write;
    driver->uv_poll_init  = tun_uv_poll_init;
    driver->add_route     = tun_add_route;
    driver->delete_route  = tun_delete_route;
    driver->close         = tun_close;
    driver->exclude_rt    = tun_exclude_rt;
    driver->commit_routes = tun_commit_routes;
    driver->get_name      = get_tun_name;

    __attribute__((cleanup(cleanup_sock))) int netdev = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (netdev == -1) {
        snprintf(error, error_len, "failed to create netdevice socket: %s", strerror(errno));
        tun_close(tun);
        return NULL;
    }

    struct sockaddr_in *ifr_addrp = (struct sockaddr_in* ) &ifr.ifr_addr;
    memset(ifr_addrp, 0, sizeof(struct sockaddr));
    ifr_addrp->sin_family = AF_INET;
    ifr_addrp->sin_addr.s_addr = tun_ip;

    if (ioctl(netdev, SIOCSIFADDR, &ifr) == -1) {
        snprintf(error, error_len, "failed to set interface address: %s", strerror(errno));
        tun_close(tun);
        return NULL;
    }
    memcpy(&driver->ip4addr, &ifr_addrp->sin_addr, sizeof(ifr_addrp->sin_addr));

    if (ioctl(netdev,SIOCGIFMTU, &ifr) == -1) {
        snprintf(error, error_len, "failed to get interface MTU: %s", strerror(errno));
        return NULL;
    }
    driver->mtu = ifr.ifr_mtu;

    ifr.ifr_flags = IFF_UP | IFF_RUNNING | IFF_NOARP | IFF_MULTICAST;
    if (ioctl(netdev, SIOCSIFFLAGS, &ifr) == -1) {
        snprintf(error, error_len, "failed to set tun up/running: %s", strerror(errno));
        tun_close(tun);
        return NULL;
    }

    /*
     * FireOS defaults OUTPUT/INPUT to DROP and only explicitly permits
     * wlan0/lo. Remove any stale rules first so tunnel restarts remain
     * idempotent.
     */
    run_command("iptables -D OUTPUT -o %s -j ACCEPT >/dev/null 2>&1", tun->name);
    run_command("iptables -D INPUT -i %s -j ACCEPT >/dev/null 2>&1", tun->name);

    run_command("iptables -I OUTPUT 1 -o %s -j ACCEPT", tun->name);
    run_command("iptables -I INPUT 1 -i %s -j ACCEPT", tun->name);

    (void)dns_ip; // no DNS maintainer on Android; see file header

    if (dns_block) {
        run_command("ip route add %s dev %s", dns_block, tun->name);
    }

    return driver;
}
