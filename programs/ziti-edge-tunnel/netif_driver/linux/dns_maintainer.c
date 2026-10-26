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

#include <arpa/inet.h>
#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <uv.h>
#include <ziti/ziti_dns.h>
#include <ziti/ziti_log.h>

#include "dns_maintainer.h"
#include "resolved_dns.h"
#include "resolvers.h"
#include "utils.h"

#define CHECK_UV(op) do{ int rc = op; if (rc < 0) ZITI_LOG(ERROR, "uv_err: %d/%s", rc, uv_strerror(rc)); } while(0)

// a burst of service updates results in a single DNS update
#define DNS_DOMAINS_DEBOUNCE_MS 500
#define MAX_FALLBACK_DNS 5
// the system's DNS servers can change without a link event, so the fallback list is refreshed when it is used
// after this long
#define FALLBACK_DNS_MAX_AGE_MS 60000
// resolved does not guarantee a change signal for its Domains property
#define WILDCARD_CHECK_MS 30000

extern void dns_set_miss_status(int code);

typedef void (*dns_updater_fn)(const char *tun, unsigned int ifindex, const char *addr, char **domains, bool default_route);

static void dns_update_resolvectl(const char *tun, unsigned int ifindex, const char *addr, char **domains, bool default_route);
static void dns_update_systemd_resolve(const char *tun, unsigned int ifindex, const char *addr, char **domains, bool default_route);

static dns_updater_fn dns_updater;
static uv_once_t dns_updater_init;

// result of one DNS update on the threadpool
struct dns_update_s {
    // the DNS updater configures routing domains (systemd-resolved)
    bool uses_domains;

    // the system's other DNS servers, for names that the tunneler receives but does not intercept
    bool has_fallback;
    size_t num_fallback;
    struct sockaddr_storage fallback[MAX_FALLBACK_DNS];
    bool wildcard_mismatch;
};

static struct {
    char tun_name[IFNAMSIZ];
    uint32_t dns_ip;

    uv_udp_t nl_udp;
    uv_timer_t update_timer;
    uv_timer_t domains_timer;
#ifndef EXCLUDE_LIBSYSTEMD_RESOLVER
    uv_timer_t wildcard_timer;
#endif

    // updates run on the threadpool one at a time, so an older snapshot never overwrites a newer one
    bool update_running;
    bool update_pending;

    // the DNS updater configures routing domains and provides fallback servers (systemd-resolved).
    // assumed until the first update tells
    bool uses_domains;

    // intercepted names and upstream availability, as last reported by ziti_dns. guarded by lock
    uv_mutex_t lock;
    char **domains;
    bool default_route;
} dns_maintainer = { .uses_domains = true };

static void free_domains(char **domains) {
    if (domains == NULL) return;
    for (char **d = domains; *d != NULL; d++) {
        free(*d);
    }
    free(domains);
}

static bool same_domains(char *const *a, char *const *b) {
    if (a == NULL || b == NULL) return a == b;
    for (; *a != NULL && *b != NULL; a++, b++) {
        if (strcmp(*a, *b) != 0) return false;
    }
    return *a == NULL && *b == NULL;
}

static char **copy_domains(char *const *domains) {
    size_t count = 0;
    while (domains && domains[count] != NULL) count++;

    char **copy = calloc(count + 1, sizeof(char *));
    if (copy == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < count; i++) {
        copy[i] = strdup(domains[i]);
        if (copy[i] == NULL) {
            free_domains(copy);
            return NULL;
        }
    }
    return copy;
}

// the updaters below shell out to systemd-resolved's tools and keep the ziti resolver a default route
static void dns_update_resolvectl(const char *tun, unsigned int ifindex, const char *addr, char **domains, bool default_route) {

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

static void dns_update_systemd_resolve(const char *tun, unsigned int ifindex, const char *addr, char **domains, bool default_route) {
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

#ifndef EXCLUDE_LIBSYSTEMD_RESOLVER
// routing domains route names below an intercepted name (e.g. www.corp.example when corp.example is intercepted)
// to the tun device exclusively, so those are forwarded to the servers that would have answered them otherwise
static void read_fallback_dns(uv_work_t *wr) {
    struct dns_update_s *update = wr->data;
    int n = systemd_resolved_get_dns_servers((int32_t) if_nametoindex(dns_maintainer.tun_name), dns_maintainer.dns_ip,
                                             update->fallback, MAX_FALLBACK_DNS);
    if (n >= 0) {
        update->has_fallback = true;
        update->num_fallback = n;
    }
}
#endif

static void set_dns(uv_work_t *wr) {
    uv_once(&dns_updater_init, find_dns_updater);

    uv_mutex_lock(&dns_maintainer.lock);
    char **domains = copy_domains(dns_maintainer.domains);
    bool default_route = dns_maintainer.default_route;
    uv_mutex_unlock(&dns_maintainer.lock);
    if (domains == NULL) {
        return;
    }

    char addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &dns_maintainer.dns_ip, addr, sizeof(addr));

    dns_updater(
            dns_maintainer.tun_name,
            if_nametoindex(dns_maintainer.tun_name),
            addr,
            domains, // the updater may change this copy
            default_route
    );
    free_domains(domains);

#ifndef EXCLUDE_LIBSYSTEMD_RESOLVER
    if (dns_updater == dns_update_systemd_resolved) {
        ((struct dns_update_s *) wr->data)->uses_domains = true;
        read_fallback_dns(wr);
    }
#endif
}

static void queue_dns_update(uv_loop_t *loop);

static void start_dns_work(uv_loop_t *loop, uv_work_cb work, uv_after_work_cb after) {
    uv_work_t *wr = calloc(1, sizeof(*wr));
    struct dns_update_s *update = calloc(1, sizeof(*update));
    if (wr == NULL || update == NULL) {
        ZITI_LOG(ERROR, "Could not allocate DNS update work");
        free(update);
        free(wr);
        return;
    }
    wr->data = update;
    int rc = uv_queue_work(loop, wr, work, after);
    if (rc != 0) {
        ZITI_LOG(ERROR, "Could not queue DNS update work: %s", uv_strerror(rc));
        free(update);
        free(wr);
        return;
    }
    dns_maintainer.update_running = true;
}

#ifndef EXCLUDE_LIBSYSTEMD_RESOLVER
static void check_wildcard(uv_work_t *wr) {
    struct dns_update_s *update = wr->data;
    int mismatch = systemd_resolved_wildcard_mismatch((int32_t) if_nametoindex(dns_maintainer.tun_name));
    if (mismatch < 0) {
        ZITI_LOG(WARN, "Could not check systemd-resolved wildcard domain: %s", strerror(-mismatch));
    } else {
        update->wildcard_mismatch = mismatch != 0;
    }
}

static void after_check_wildcard(uv_work_t *wr, int status) {
    struct dns_update_s *update = wr->data;
    bool mismatch = status == 0 && update->wildcard_mismatch;
    free(update);
    dns_maintainer.update_running = false;
    if (mismatch || dns_maintainer.update_pending) {
        dns_maintainer.update_pending = false;
        queue_dns_update(wr->loop);
    }
    free(wr);
}

static void on_wildcard_check(uv_timer_t *timer) {
    if (dns_maintainer.update_running || !dns_maintainer.uses_domains ||
        dns_updater != dns_update_systemd_resolved) return;

    uv_mutex_lock(&dns_maintainer.lock);
    bool default_route = dns_maintainer.default_route;
    uv_mutex_unlock(&dns_maintainer.lock);
    if (default_route) start_dns_work(timer->loop, check_wildcard, after_check_wildcard);
}
#endif

static void after_set_dns(uv_work_t *wr, int status) {
    ZITI_LOG(DEBUG, "DNS update: %d", status);
    struct dns_update_s *update = wr->data;
    if (status == 0) {
        dns_maintainer.uses_domains = update->uses_domains;
        if (update->has_fallback) {
            ziti_dns_set_fallback_upstream(wr->loop, update->fallback, update->num_fallback, FALLBACK_DNS_MAX_AGE_MS);
        }
    }
    free(update);

    dns_maintainer.update_running = false;
    if (dns_maintainer.update_pending) {
        dns_maintainer.update_pending = false;
        queue_dns_update(wr->loop);
    }
    free(wr);
}

static void queue_dns_update(uv_loop_t *loop) {
    if (dns_maintainer.update_running) {
        dns_maintainer.update_pending = true;
        return;
    }
    ZITI_LOG(DEBUG, "queuing DNS update");
    start_dns_work(loop, set_dns, after_set_dns);
}

static void on_dns_update_time(uv_timer_t *t) {
    queue_dns_update(t->loop);
}

static void do_dns_update(uv_loop_t *loop, int delay) {
    uv_timer_start(&dns_maintainer.update_timer, on_dns_update_time, delay, 0);
}

static void on_dns_domains_timer(uv_timer_t *t) {
    char **domains = ziti_dns_get_domains();
    if (domains == NULL) {
        return;
    }
    bool default_route = ziti_dns_has_upstream();

    uv_mutex_lock(&dns_maintainer.lock);
    bool changed = !same_domains(domains, dns_maintainer.domains) || default_route != dns_maintainer.default_route;
    if (changed) {
        free_domains(dns_maintainer.domains);
        dns_maintainer.domains = domains;
        dns_maintainer.default_route = default_route;
    }
    uv_mutex_unlock(&dns_maintainer.lock);

    if (!changed) {
        free_domains(domains);
        return;
    }

    size_t count = 0;
    while (domains[count] != NULL) count++;
    ZITI_LOG(DEBUG, "intercepted DNS names changed: %zu names, default route: %s", count, default_route ? "yes" : "no");
    // other DNS updaters do not use the names. an update delayed after a link change (update_timer) stays
    // scheduled, so it still runs after systemd-resolved has applied the change
    if (dns_maintainer.uses_domains) {
        queue_dns_update(t->loop);
    }
}

void dns_maintainer_domains_changed(netif_handle dev, uv_loop_t *loop) {
    // the timer is only initialized when the tunneler manages DNS
    if (dns_maintainer.domains_timer.loop == NULL) {
        return;
    }
    uv_timer_start(&dns_maintainer.domains_timer, on_dns_domains_timer, DNS_DOMAINS_DEBOUNCE_MS, 0);
}

#ifndef EXCLUDE_LIBSYSTEMD_RESOLVER
static void after_read_fallback_dns(uv_work_t *wr, int status) {
    struct dns_update_s *update = wr->data;
    if (status == 0 && update->has_fallback) {
        ziti_dns_set_fallback_upstream(wr->loop, update->fallback, update->num_fallback, FALLBACK_DNS_MAX_AGE_MS);
    }
    free(update);

    dns_maintainer.update_running = false;
    if (dns_maintainer.update_pending) {
        dns_maintainer.update_pending = false;
        queue_dns_update(wr->loop);
    }
    free(wr);
}
#endif

void dns_maintainer_refresh_fallback(netif_handle dev, uv_loop_t *loop) {
#ifndef EXCLUDE_LIBSYSTEMD_RESOLVER
    // a running update reads the servers too. refreshes run in turn with updates, so servers are never applied
    // out of order
    if (!dns_maintainer.uses_domains || dns_maintainer.update_running) {
        return;
    }
    ZITI_LOG(DEBUG, "refreshing fallback DNS servers");
    start_dns_work(loop, read_fallback_dns, after_read_fallback_dns);
#endif
}

static void nl_alloc(uv_handle_t *h, size_t req, uv_buf_t *b) {
    b->base = malloc(req);
    b->len = req;
}

static void on_nl_message(uv_udp_t *nl, ssize_t len, const uv_buf_t *buf, const struct sockaddr *addr, unsigned int i) {
    // delay to make sure systemd-resolved finished its own updates
    do_dns_update(nl->loop, 3000);
    if (buf->base) free(buf->base);
}

void dns_maintainer_init(uv_loop_t *loop, const char *tun_name, uint32_t dns_ip) {
    strncpy(dns_maintainer.tun_name, tun_name, sizeof(dns_maintainer.tun_name));
    dns_maintainer.dns_ip = dns_ip;
    uv_mutex_init(&dns_maintainer.lock);

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

    CHECK_UV(uv_udp_recv_start(&dns_maintainer.nl_udp, nl_alloc, on_nl_message));

    uv_timer_init(loop, &dns_maintainer.update_timer);
    uv_unref((uv_handle_t *) &dns_maintainer.update_timer);
    uv_timer_init(loop, &dns_maintainer.domains_timer);
    uv_unref((uv_handle_t *) &dns_maintainer.domains_timer);
#ifndef EXCLUDE_LIBSYSTEMD_RESOLVER
    uv_timer_init(loop, &dns_maintainer.wildcard_timer);
    uv_unref((uv_handle_t *) &dns_maintainer.wildcard_timer);
    uv_timer_start(&dns_maintainer.wildcard_timer, on_wildcard_check, WILDCARD_CHECK_MS, WILDCARD_CHECK_MS);
#endif
    do_dns_update(loop, 0);
}
