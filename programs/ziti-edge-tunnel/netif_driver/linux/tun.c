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

#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
//#include <linux/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>

#include <ziti/ziti_log.h>
#include <ziti/ziti_dns.h>

#include "dns_maintainer.h"
#include "tun.h"
#include "utils.h"

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
    if (tun->route_updates == NULL) {
        tun->route_updates = calloc(1, sizeof(*tun->route_updates));
    }
    model_map_set(tun->route_updates, dest, (void*)(uintptr_t)true);
}

int tun_delete_route(netif_handle tun, const char *dest) {
    if (tun->route_updates == NULL) {
        tun->route_updates = calloc(1, sizeof(*tun->route_updates));
    }
    model_map_set(tun->route_updates, dest, (void*)(uintptr_t)false);
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

    uv_fs_t tmp_req = {0};
    uv_file routes_file = uv_fs_mkstemp(wr->loop, &tmp_req, "/tmp/ziti-tunnel-routes.XXXXXX", NULL);
    if (routes_file < 0) {
        ZITI_LOG(ERROR, "failed to create temp file for route updates %d/%s", routes_file, uv_strerror(routes_file));
        uv_fs_req_cleanup(&tmp_req);
        return;
    }

    // get route deletes first
    static const char *const verbs[] = {
        "delete",
        "add",
    };
    char buf[1024];
    for (size_t i = 0; i < sizeof verbs/sizeof verbs[0]; i++) {
        const char *const verb = verbs[i];
        const char *prefix;
        const void *value;

        MODEL_MAP_FOREACH(prefix, value, cmd->updates) {
            // action == 0: delete
            // action == 1: add
            unsigned action = (uintptr_t) value;
            if (action == i) {
                int len = snprintf(buf, sizeof(buf), "route %s %s dev %s\n", verb, prefix, cmd->tun->name);
                if (len < 0 || (size_t) len >= sizeof buf) {
                    if (len > 0) errno = ENOMEM;
                    ZITI_LOG(ERROR, "route updates failed %d/%s", -errno, strerror(errno));
                    goto close_file;
                }

                uv_fs_t write_req;
                uv_buf_t b = uv_buf_init(buf, len);
                int rc = uv_fs_write(wr->loop, &write_req, routes_file, &b, 1, -1, NULL);
                uv_fs_req_cleanup(&write_req);
                /* if an incomplete write is encountered, bail.
                 * Don't want to execute clipped commands
                 */
                if (rc < len) {
                    if (rc > 0) rc = UV_EIO;
                    ZITI_LOG(ERROR, "route updates failed %d/%s", rc, uv_strerror(rc));
                    goto close_file;
                }
            }
        }
    }

    run_command("ip -force -batch %s", uv_fs_get_path(&tmp_req));

close_file: ; /* declaration is not a statement */
    uv_fs_t unlink_req;
    (void) uv_fs_unlink(wr->loop, &unlink_req, uv_fs_get_path(&tmp_req), NULL);
    uv_fs_req_cleanup(&unlink_req);
    uv_fs_req_cleanup(&tmp_req);

    uv_fs_t close_req;
    (void) uv_fs_close(wr->loop, &close_req, routes_file, NULL);
    uv_fs_req_cleanup(&close_req);
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
    char cmd[1024];
    char route[128];
    FILE *cmdpipe = NULL;
    int n;

    n = snprintf(cmd, sizeof cmd,
        "ip -o route show match %s table all | "
        "awk '/dev %s/ { next; } { if (match($0, / metric ([^ ]+)/)) { metric = substr($0, RSTART, RLENGTH); } printf \"%%s %%s%%s\\n\", $2, $3, metric; }'",
        addr, dev->name);
    if (n > 0 && (size_t) n < sizeof cmd) {
        ZITI_LOG(DEBUG, "popen(%s)", cmd);
        cmdpipe = popen(cmd, "r");
    } else {
        errno = ENOMEM;
    }

    if (cmdpipe == NULL) {
        ZITI_LOG(WARN, "ip route cmd popen(%s) failed [%d:%s]", cmd, errno, strerror(errno));
        return -1;
    }

    errno = 0;
    size_t size = fread(route, 1, sizeof route, cmdpipe);
    int saved_errno = errno;
    int ferr = ferror(cmdpipe);
    (void) pclose(cmdpipe);
    if (ferr) {
        errno = saved_errno ? saved_errno : EIO;
        ZITI_LOG(WARN, "ip route cmd I/O failed [%d:%s]", errno, strerror(errno));
        return -1;
    }

    // only look at first line
    char *p = memchr(route, '\n', size);
    // was a full line read?
    if (p == NULL || p == route) {
        ZITI_LOG(WARN, "failed to retrieve destination route");
        return -1;
    }
    *p = 0;

    ZITI_LOG(DEBUG, "route is %s %s", addr, route);

    return run_command("ip route replace %s %s", addr, route);
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

    driver->handle       = tun;
    driver->read         = tun_read;
    driver->write        = tun_write;
    driver->uv_poll_init = tun_uv_poll_init;
    driver->add_route    = tun_add_route;
    driver->delete_route = tun_delete_route;
    driver->close        = tun_close;
    driver->exclude_rt   = tun_exclude_rt;
    driver->commit_routes = tun_commit_routes;
    driver->get_name = get_tun_name;

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

    if (dns_ip) {
        dns_maintainer_init(loop, tun->name, dns_ip);
        driver->dns_domains_changed = dns_maintainer_domains_changed;
        driver->dns_refresh_fallback = dns_maintainer_refresh_fallback;
    }

    if (dns_block) {
        run_command("ip route add %s dev %s", dns_block, tun->name);
    }

    return driver;
}

netif_driver tap_open(uv_loop_t *loop, char *error, size_t error_len) {
    if (error != NULL) {
        memset(error, 0, error_len * sizeof(char));
    }

    struct netif_handle_s *tap = calloc(1, sizeof(struct netif_handle_s));
    if (tap == NULL) {
        if (error != NULL) {
            snprintf(error, error_len, "failed to allocate tap");
        }
        return NULL;
    }

    if ((tap->fd = open(DEVTUN, O_RDWR|O_CLOEXEC)) < 0) {
        if (error != NULL) {
            snprintf(error, error_len,"open %s failed", DEVTUN);
        }
        free(tap);
        return NULL;
    }

    struct ifreq ifr = { .ifr_name = "ziti-tap%d", .ifr_flags = IFF_TAP | IFF_NO_PI };

    if (ioctl(tap->fd, TUNSETIFF, &ifr) < 0) {
        if (error != NULL) {
            snprintf(error, error_len, "failed to open tap device:%s", strerror(errno));
        }
        tun_close(tap);
        return NULL;
    }

    strncpy(tap->name, ifr.ifr_name, sizeof(tap->name));

    struct netif_driver_s *driver = calloc(1, sizeof(struct netif_driver_s));
    if (driver == NULL) {
        if (error != NULL) {
            snprintf(error, error_len, "failed to allocate netif_device_s");
        }
        tun_close(tap);
        return NULL;
    }

    driver->handle       = tap;
    driver->read         = tun_read;
    driver->write        = tun_write;
    driver->uv_poll_init = tun_uv_poll_init;
    driver->add_route    = tun_add_route;
    driver->delete_route = tun_delete_route;
    driver->close        = tun_close;
    driver->exclude_rt   = tun_exclude_rt;
    driver->commit_routes = tun_commit_routes;
    driver->get_name = get_tun_name;

    __attribute__((cleanup(cleanup_sock))) int netdev = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (netdev == -1) {
        snprintf(error, error_len, "failed to create netdevice socket: %s", strerror(errno));
        tun_close(tap);
        return NULL;
    }

    if (ioctl(netdev,SIOCGIFMTU, &ifr) == -1) {
        snprintf(error, error_len, "failed to get interface MTU: %s", strerror(errno));
        return NULL;
    }
    driver->mtu = ifr.ifr_mtu;

    /* the kernel should have given our interface a link-local hardware address.
     * configure the lwip netif with the actual interface address.
     *
     * wait for kernel to configure the interface. without this we get an uninitialized (an nonzero) value.
     * todo tried checking ifr_hwaddr.sa_family == ARPHRD_ETHER, maybe look for another way to validate hwaddr is ready.
     */
    uv_sleep(100);
    if (ioctl(netdev, SIOCGIFHWADDR, &ifr) < 0) {
        snprintf(error, error_len, "failed to set hardware address: %s", strerror(errno));
        tun_close(tap);
        return NULL;
    }
    memcpy(driver->hwaddr, ifr.ifr_hwaddr.sa_data, 6);
    driver->hwaddr_len = 6;
    ifr.ifr_flags = IFF_UP | IFF_RUNNING | IFF_NOARP | IFF_MULTICAST;

    if (ioctl(netdev, SIOCSIFFLAGS, &ifr) == -1) {
        snprintf(error, error_len, "failed to set tap up/running: %s", strerror(errno));
        tun_close(tap);
        return NULL;
    }

    return driver;
}