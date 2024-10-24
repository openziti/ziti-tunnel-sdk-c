/*
 Copyright 2021 NetFoundry Inc.

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
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>

#include <sysexits.h>

#include <uv.h>

#include <ziti/ziti_log.h>
#include <ziti/ziti_dns.h>

#include "resolvers.h"
#include "tun.h"
#include "utils.h"
#include "libiproute.h"
#include "capability.h"

#ifndef DEVTUN
#define DEVTUN "/dev/net/tun"
#endif

/**
 * Let's keep the ZET_RT_TABLE in 0..255:
 * - busybox routing tables ids are restricted to 0..1023.
 * - iproute2 stores table ids 0..255 in rtmsg.rtm_table; otherwise rtattr RTA_TABLE is used
 */
#ifndef ZET_RT_TABLE
#define ZET_RT_TABLE ((unsigned char)'Z')
#endif

/**
 * ZET_POLICY_PREF_BASE in 0..32767
 * 0: local
 * 32766: main
 * 32767: default
 *
 * 'Ze' = 0x5A65 = 23141
 */
#ifndef ZET_POLICY_PREF_BASE
#define ZET_POLICY_PREF_BASE (((unsigned char)'Z')<<8|'e')
#endif

#define ZET_BYPASS_MARK 0xC000000
#define ZET_BYPASS_MASK 0xC000000

/*
 * ip link set tun0 up
 * ip addr add 169.254.1.1 remote 169.254.0.0/16 dev tun0
 */

#if 0
#define IP_ADDR_ARGS "addr add %d.%d.%d.%d/24 dev %s"
#define IP_UP_ARGS "link set %s up"
#define IP_BIN "/sbin/ip "
#endif

#define CHECK_UV(op) do{ int rc = op; if (rc < 0) ZITI_LOG(ERROR, "uv_err: %d/%s", rc, uv_strerror(rc)); } while(0)


static int ZET__is_rt_table_main(struct netif_handle_s *tun);

extern void dns_set_miss_status(int code);

static void dns_update_resolvectl(const char* tun, unsigned int ifindex, const char* addr);
static void dns_update_systemd_resolve(const char* tun, unsigned int ifindex, const char* addr);

static void (*dns_updater)(const char* tun, unsigned int ifindex, const char* addr);
static uv_once_t dns_updater_init;

static struct {
    char tun_name[IFNAMSIZ];
    uint32_t dns_ip;

    uv_udp_t nl_udp;
    uv_timer_t update_timer;
} dns_maintainer;

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
    struct rt_process_cmd *const cmd = wr->data;
    struct netif_handle_s *const tun = cmd->tun;

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
    static const char *const formats[2] = {
        "route %s %s dev %s table %d\n",
        "route %s %s dev %s"
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

                int len = snprintf(buf, sizeof(buf),
                    formats[!!ZET__is_rt_table_main(tun)],
                    verb, prefix, tun->name, tun->route_table);
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

static void dns_update_resolvectl(const char* tun, unsigned int ifindex, const char* addr) {

    run_command(RESOLVECTL " dns %s %s", tun, addr);
    int s = run_command_ex(false, RESOLVECTL " domain | grep -F -v '%s' | grep -F -q '~.'",
                           dns_maintainer.tun_name);
    // set wildcard domain if any other resolvers set it.
    if (s == 0) {
        run_command(RESOLVECTL " domain %s '~.'", dns_maintainer.tun_name);
    } else {
        // Use busctl due to systemd version differences fixed in systemd>=240
        run_command(BUSCTL " call %s %s %s SetLinkDomains 'ia(sb)' %u 0",
                RESOLVED_DBUS_NAME,
                RESOLVED_DBUS_PATH,
                RESOLVED_DBUS_MANAGER_INTERFACE,
                ifindex);
    }
    run_command(RESOLVECTL " dnssec %s no", dns_maintainer.tun_name);
    run_command(RESOLVECTL " reset-server-features");
    run_command(RESOLVECTL " flush-caches");
}

static void dns_update_systemd_resolve(const char* tun, unsigned int ifindex, const char* addr) {
    run_command(SYSTEMD_RESOLVE " -i %s --set-dns=%s", tun, addr);
    int s = run_command_ex(false, SYSTEMD_RESOLVE " --status | grep -F 'DNS Domain' | grep -F -q '~.'");
    // set wildcard domain if any other resolvers set it.
    if (s == 0) {
        run_command(SYSTEMD_RESOLVE " -i %s --set-domain='~.'", dns_maintainer.tun_name);
    } else {
        // Use busctl due to systemd version differences fixed in systemd>=240
        run_command(BUSCTL " call %s %s %s SetLinkDomains 'ia(sb)' %u 0",
                RESOLVED_DBUS_NAME,
                RESOLVED_DBUS_PATH,
                RESOLVED_DBUS_MANAGER_INTERFACE,
                ifindex);
    }
    run_command(SYSTEMD_RESOLVE " --set-dnssec=no --interface=%s", dns_maintainer.tun_name);
    run_command(SYSTEMD_RESOLVE " --reset-server-features");
    run_command(SYSTEMD_RESOLVE " --flush-caches");
}

static void find_dns_updater() {
#ifndef EXCLUDE_LIBSYSTEMD_RESOLVER
    if(try_libsystemd_resolver(dns_maintainer.tun_name)) {
        dns_updater = dns_update_systemd_resolved;
        return;
    }
#endif
    if (is_executable(BUSCTL)) {
        if (run_command_ex(false, BUSCTL " status %s > /dev/null 2>&1", RESOLVED_DBUS_NAME) == 0) {
            if (is_executable(RESOLVECTL)) {
                dns_updater = dns_update_resolvectl;
                return;
            } else if (is_executable(SYSTEMD_RESOLVE)) {
                dns_updater = dns_update_systemd_resolve;
                return;
            } else {
                ZITI_LOG(WARN, "systemd-resolved DBus name found, but could not find a way to configure systemd-resolved");
            }
        } else {
            ZITI_LOG(TRACE, "systemd-resolved DBus name is NOT acquired");
        }
    }

    if (!(is_systemd_resolved_primary_resolver())) {
        // On newer systems, RESOLVCONF is a symlink to RESOLVECTL
        // By now, we know systemd-resolved is not available
        if (is_executable(RESOLVCONF) && !(is_resolvconf_systemd_resolved())) {
            dns_updater = dns_update_resolvconf;
            return;
        }

        ZITI_LOG(WARN, "Adding ziti resolver to /etc/resolv.conf. Ziti DNS functionality may be impaired");
        dns_updater = dns_update_etc_resolv;
        dns_set_miss_status(DNS_REFUSE);
    } else {
        ZITI_LOG(ERROR, "Refusing to alter DNS configuration. /etc/resolv.conf is a symlink to systemd-resolved, but no systemd resolver succeeded");
        exit(1);
    }
}

static void set_dns(uv_work_t *wr) {
    uv_once(&dns_updater_init, find_dns_updater);
    dns_updater(
            dns_maintainer.tun_name,
            if_nametoindex(dns_maintainer.tun_name),
            inet_ntoa(*(struct in_addr*)&dns_maintainer.dns_ip)
    );
}

static void after_set_dns(uv_work_t *wr, int status) {
    ZITI_LOG(DEBUG, "DNS update: %d", status);
    free(wr);
}

static void on_dns_update_time(uv_timer_t *t) {
    ZITI_LOG(DEBUG, "queuing DNS update");
    uv_work_t *wr = calloc(1, sizeof(uv_work_t));
    uv_queue_work(t->loop, wr, set_dns, after_set_dns);

}
static void do_dns_update(uv_loop_t *loop, int delay) {
    uv_timer_start(&dns_maintainer.update_timer, on_dns_update_time, delay, 0);
}

void nl_alloc(uv_handle_t *h, size_t req, uv_buf_t *b) {
    b->base = malloc(req);
    b->len = req;
}

void on_nl_message(uv_udp_t *nl, ssize_t len, const uv_buf_t *buf, const struct sockaddr * addr, unsigned int i) {
    // delay to make sure systemd-resolved finished its own updates
    do_dns_update(nl->loop, 3000);
    if (buf->base) free(buf->base);
}

static void init_dns_maintainer(uv_loop_t *loop, const char *tun_name, uint32_t dns_ip) {
    strncpy(dns_maintainer.tun_name, tun_name, sizeof(dns_maintainer.tun_name));
    dns_maintainer.dns_ip = dns_ip;

    ZITI_LOG(DEBUG, "setting up NETLINK listener");
    struct sockaddr_nl local = {0};
    local.nl_family = AF_NETLINK;
    local.nl_groups = RTMGRP_LINK;// | RTMGRP_IPV4_ROUTE;

    int s = socket(AF_NETLINK, SOCK_DGRAM|SOCK_CLOEXEC, NETLINK_ROUTE);
    if ( s < 0) {
        ZITI_LOG(ERROR, "failed to open netlink socket: %d/%s", errno, strerror(errno));
    }
    if (bind(s, (struct sockaddr *)&local, sizeof(local)) < 0) {
        ZITI_LOG(ERROR, "failed to bind %d/%s", errno, strerror(errno));
    }

    CHECK_UV(uv_udp_init(loop, &dns_maintainer.nl_udp));
    uv_unref((uv_handle_t *) &dns_maintainer.nl_udp);
    CHECK_UV(uv_udp_open(&dns_maintainer.nl_udp, s));

    struct sockaddr_nl kern = {0};
    kern.nl_family = AF_NETLINK;
    kern.nl_groups = 0;

    CHECK_UV(uv_udp_recv_start(&dns_maintainer.nl_udp, nl_alloc, on_nl_message));

    uv_timer_init(loop, &dns_maintainer.update_timer);
    uv_unref((uv_handle_t *) &dns_maintainer.update_timer);
    do_dns_update(loop, 0);
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

static int tun_exclude_rt_noop(netif_handle dev, uv_loop_t *l, const char *addr) {
  /**
   * When the isolated routing table feature is active, communication between the controller and edge router does not need to be explicitly defined.
   * These sockets are marked with SO_MARK, allowing them to bypass the Ziti-dedicated routing table, which contains the Ziti-specific routes, and use
   * the routes available in the `main` routing table.
   */
    (void) dev;
    (void) l;
    (void) addr;
    return 0;
}

static int
ZET__route_table(const struct netif_options *opts)
{
    return (opts->use_rt_main || run_command("ip -4 rule show >/dev/null") != 0)
      ? RT_TABLE_MAIN : ZET_RT_TABLE;
}

static int
ZET__is_rt_table_main(struct netif_handle_s *tun)
{
  return tun->route_table == RT_TABLE_MAIN;
}

static void
ZET__rpdb_init(struct netif_handle_s *tun)
{
    rtnetlink h;
    int err;

    if (ZET__is_rt_table_main(tun))
        return;

    if ((err = rtnetlink_new(&h)) < 0) {
          ZITI_LOG(ERROR, "failed to open netlink socket: %d/%s", errno, strerror(errno));
          return;
    }

    err = zt_iprule_modify(h, IPRULE_ADD,
        "not from 0.0.0.0/0 fwmark 0x%x/0x%x pref %d lookup %d",
        ZET_BYPASS_MARK, ZET_BYPASS_MASK, ZET_POLICY_PREF_BASE, tun->route_table);
    if (err < 0 && err != -EEXIST)
        ZITI_LOG(ERROR, "error(s) encountered while updating ipv4 routing policy database.");

    err = zt_iprule_modify(h, IPRULE_ADD,
        "not from ::/0 fwmark 0x%x/0x%x pref %d lookup %d",
        ZET_BYPASS_MARK, ZET_BYPASS_MASK, ZET_POLICY_PREF_BASE, tun->route_table);
    if (err < 0 && err != -EEXIST && err != -EAFNOSUPPORT)
        ZITI_LOG(ERROR, "error(s) encountered while updating ipv6 routing policy database.");

    rtnetlink_free(h);
}

static void cleanup_sock(const int *fd) {
    if (fd && *fd != -1) {
        close(*fd);
    }
}

netif_driver tun_open(uv_loop_t *loop, uint32_t tun_ip, uint32_t dns_ip, const char *dns_block, char *error, size_t error_len,
    const struct netif_options *opts) {
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

    struct ifreq ifr = { .ifr_name = "ziti%d",
                         .ifr_flags = IFF_TUN | IFF_NO_PI };

    if (ioctl(tun->fd, TUNSETIFF, &ifr) < 0) {
        if (error != NULL) {
            snprintf(error, error_len, "failed to open tun device:%s", strerror(errno));
        }
        tun_close(tun);
        return NULL;
    }

    strncpy(tun->name, ifr.ifr_name, sizeof(tun->name));

    tun->route_table = ZET__route_table(opts);

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
    driver->exclude_rt   = ZET__is_rt_table_main(tun) ? tun_exclude_rt : tun_exclude_rt_noop;
    driver->commit_routes = tun_commit_routes;

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
        snprintf(error, error_len, "failed to set tun address: %s", strerror(errno));
        tun_close(tun);
        return NULL;
    }

    ifr.ifr_flags = IFF_UP | IFF_RUNNING | IFF_NOARP | IFF_MULTICAST;

    if (ioctl(netdev, SIOCSIFFLAGS, &ifr) == -1) {
        snprintf(error, error_len, "failed to set tun up/running: %s", strerror(errno));
        tun_close(tun);
        return NULL;
    }

    ZET__rpdb_init(tun);

    if (dns_ip) {
        init_dns_maintainer(loop, tun->name, dns_ip);
    }

    if (dns_block) {
        run_command("ip route add %s dev %s table %d",
            dns_block, tun->name, tun->route_table);
    }

    return driver;
}

static int make_bypass_socket(const struct addrinfo *ai, bool blocking)
{
    int blockmode = blocking ? 0 : SOCK_NONBLOCK;
    int sd;

    sd = socket(ai->ai_family, ai->ai_socktype|SOCK_CLOEXEC|blockmode,
        ai->ai_protocol);
    if (sd < 0) {
        int uv_err = uv_translate_sys_error(errno);

        ZITI_LOG(ERROR, "Failed to create socket: %d/%s", uv_err, uv_strerror(uv_err));
        return uv_err;
    }

    int mark = ZET_BYPASS_MARK;
    int sys_rc;

    ziti_cap_assert(ZITI_CAP_NETADMIN);
    sys_rc = setsockopt(sd, SOL_SOCKET, SO_MARK, &mark, sizeof mark);
    ziti_cap_restore();

    if (sys_rc < 0) {
        int uv_err = uv_translate_sys_error(errno);

        ZITI_LOG(ERROR, "Failed to configure SO_MARK on socket: %d/%s",
            uv_err, uv_strerror(uv_err));
        (void) close(sd);
        return uv_err;
    }

    return sd;
}

/**
 * Override tlsuv's socket factory. This factory is used to create
 * the sockets used for the controller and edge router communication.
 */
uv_os_sock_t tlsuv_socket(const struct addrinfo *ai, bool blocking)
{
    uv_os_sock_t /* int */ sd;

    sd = make_bypass_socket(ai, blocking);
    if (sd < 0)
        exit(EX_OSERR);

    int nodelay = 1;
    if (setsockopt(sd, SOL_TCP, TCP_NODELAY, &nodelay, sizeof nodelay) < 0
        && errno != ENOPROTOOPT) {
        int uv_err = uv_translate_sys_error(errno);

        ZITI_LOG(WARN, "Failed to set TCP_NODELAY on socket: %d/%s", uv_err, uv_strerror(uv_err));
    }

    return sd;
}

/**
 * Override ziti_hosting_cbs socket factory. This factory is used to create
 * the sockets used for `hosted` services.
 */
int
ziti_tunnel_hosting_socket(uv_os_sock_t *psock, const struct addrinfo *ai)
{
    uv_os_sock_t sd;

    sd = make_bypass_socket(ai, true);
    if (sd < 0) {
        int uv_err = uv_translate_sys_error(errno);

        *psock = -1;
        return uv_err;
    }

    *psock = sd;

    return 0;
}
