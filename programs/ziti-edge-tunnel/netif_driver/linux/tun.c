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

#include <ziti/ziti_log.h>
#include <ziti/ziti_dns.h>
#include <stdbool.h>

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

#define CHECK_UV(op) do{ int rc = op; if (rc < 0) ZITI_LOG(ERROR, "uv_err: %d/%s", rc, uv_strerror(rc)); } while(0)

#define RESOLVECTL "resolvectl"

extern void dns_set_miss_status(int code);

static void dns_update_resolvectl(const char* tun, const char* addr);
static void dns_update_systemd_resolve(const char* tun, const char* addr);
static void dns_update_resolvconf(const char* tun, const char* addr);
static void dns_update_etc_resolv(const char* tun, const char* addr);

static void (*dns_updater)(const char* tun, const char* addr);
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

static int run_command_va(bool log_nonzero_ec, const char* cmd, va_list args) {
    char cmdline[1024];
    vsprintf(cmdline, cmd, args);

    int rc = system(cmdline);
    if (rc != 0 && log_nonzero_ec) {
        ZITI_LOG(ERROR, "cmd{%s} failed: %d/%d/%s\n", cmdline, rc, errno, strerror(errno));
    }
    ZITI_LOG(DEBUG, "system(%s) returned %d", cmdline, rc);
    return WEXITSTATUS(rc);
}

static int run_command(const char *cmd, ...) {
    va_list args;
    va_start(args, cmd);
    int r = run_command_va(true, cmd, args);
    va_end(args);
    return r;
}

static int run_command_ex(bool log_nonzero_ec, const char *cmd, ...) {
    va_list args;
    va_start(args, cmd);
    int r = run_command_va(log_nonzero_ec, cmd, args);
    va_end(args);
    return r;
}

static void find_dns_updater() {
    struct dns_cmd {
        const char *path;
        void (* update_fn)(const char* tun, const char* addr);
    };

    static struct dns_cmd dns_cmds[] = {
            {
                    .path = "/usr/bin/resolvectl",
                    .update_fn = dns_update_resolvectl,
            },
            {
                    .path = "/usr/bin/systemd-resolve",
                    .update_fn = dns_update_systemd_resolve,
            },
            {
                    .path = "/usr/sbin/resolvconf",
                    .update_fn = dns_update_resolvconf
            },
            {0}
    };

    uv_loop_t *l = dns_maintainer.update_timer.loop;
    for (int idx = 0; dns_cmds[idx].path != NULL; idx++) {
        uv_fs_t req = {0};
        if (uv_fs_stat(l, &req, dns_cmds[idx].path, NULL) == 0) {
            dns_updater = dns_cmds[idx].update_fn;
            return;
        }
    }

    ZITI_LOG(ERROR, "could not find a way to configure system resolver. Ziti DNS functionality will be impaired");
    dns_updater = dns_update_etc_resolv;
}

static void set_dns(uv_work_t *wr) {
    uv_once(&dns_updater_init, find_dns_updater);
    dns_updater(dns_maintainer.tun_name, inet_ntoa(*(struct in_addr*)&dns_maintainer.dns_ip));
}

static void dns_update_resolvectl(const char* tun, const char* addr) {
    run_command(RESOLVECTL " dns %s %s", tun, addr);
    int s = run_command_ex(false, RESOLVECTL " domain | fgrep -v '%s' | fgrep -q '~.'",
                           dns_maintainer.tun_name);
    char *domain = "";
    // set wildcard domain if any other resolvers set it.
    if (s == 0) {
        domain = "~.";
    }
    run_command(RESOLVECTL " domain %s '%s'", dns_maintainer.tun_name, domain);
}

static void dns_update_systemd_resolve(const char* tun, const char* addr) {
    run_command("systemd-resolve -i %s --set-dns=%s", tun, addr);
    int s = run_command_ex(false, "systemd-resolve --status | fgrep  'DNS Domain' | fgrep -q '~.'");
    char *domain = "";
    // set wildcard domain if any other resolvers set it.
    if (s == 0) {
        domain = "--set-domain=~.";
        run_command("systemd-resolve -i %s %s", dns_maintainer.tun_name, domain);
    }
}

static void dns_update_resolvconf(const char* tun, const char* addr) {
    run_command("echo 'nameserver %s' | resolvconf -a %s", addr, tun);
}

static void dns_update_etc_resolv(const char* tun, const char* addr) {
    int found = run_command("grep -q '^nameserver %s' /etc/resolv.conf", addr);

    if (found != 0) {
        run_command("sed -z -i 's/nameserver/nameserver %s\\nnameserver/' /etc/resolv.conf", addr);
    }

    dns_set_miss_status(DNS_REFUSE);
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

    int s = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if ( s < 0) {
        ZITI_LOG(ERROR, "failed to open netlink socket: %d/%s", errno, strerror(errno));
    }
    if (bind(s, &local, sizeof(local)) < 0) {
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
    char def_route[128];
    FILE *def_rt = popen("ip route show default", "r");
    int def_rt_size = (int)fread(def_route, 1, sizeof(def_route), def_rt);

    // only look at first line
    char *p = strchr(def_route, '\n');
    if (p != NULL) {
        *p = 0;
    }

    ZITI_LOG(DEBUG, "default route is '%.*s'", def_rt_size, def_route);
    pclose(def_rt);

    const char *type = NULL;
    if ((p = strstr(def_route, "via ")) != NULL) {
        type = "via";
    } else if ((p = strstr(def_route, "dev ")) != NULL) {
        type = "dev";
    } else {
        ZITI_LOG(WARN, "could not find default route");
        return -1;
    }

    char *gw = p + 4;
    char *endgw = strchr(gw, ' ');
    int gw_len = (int)(endgw - gw);

    return run_command("ip route replace %s %s %.*s", addr, type, gw_len, gw);
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
    driver->exclude_rt   = tun_exclude_rt;

    run_command("ip link set %s up", tun->name);
    run_command("ip addr add %s dev %s", inet_ntoa(*(struct in_addr*)&tun_ip), tun->name);

    if (dns_ip) {
        init_dns_maintainer(loop, tun->name, dns_ip);
    }

    if (dns_block) {
        run_command("ip route add %s dev %s", dns_block, tun->name);
    }

    return driver;
}