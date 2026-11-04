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

#ifndef EXCLUDE_LIBSYSTEMD_RESOLVER

#include <ctype.h>
#include <errno.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include <uv.h>
#include <ziti/ziti_dns.h>
#include <ziti/ziti_log.h>

#include "libsystemd_dl.h"
#include "resolved_dns.h"
#include "resolvers.h"

/*
 * systemd-resolved routes a query (man systemd-resolved, "Protocols and routing")
 *  1. to the links with the longest routing domain that matches the name, or, if no routing domain matches,
 *  2. to the global DNS servers and the servers of links that are a default route; if there are none at all,
 *     to its built-in fallback servers (FallbackDNS).
 * The tunnel claims the intercepted names as routing-only domains of its link, so they are no longer raced against
 * other links' servers (rule 1). Names below an intercepted name then reach only the tunnel, which forwards them to
 * the servers of rule 2 (systemd_resolved_get_dns_servers).
 */

#define RESOLVED_DBUS_LINK_INTERFACE "org.freedesktop.resolve1.Link"

// domains systemd-resolved accepts per link (LINK_SEARCH_DOMAINS_MAX). older versions accept fewer, which is
// handled by retrying with half the limit, down to RESOLVED_LINK_DOMAINS_MIN
#ifndef RESOLVED_LINK_DOMAINS_MAX
#define RESOLVED_LINK_DOMAINS_MAX 1024
#endif
#define RESOLVED_LINK_DOMAINS_MIN 32

static void free_names(char **names) {
    for (char **n = names; n && *n; n++) {
        free(*n);
    }
    free(names);
}

static bool contains_name(char *const *names, const char *name) {
    for (char *const *n = names; n && *n; n++) {
        if (strcmp(*n, name) == 0) return true;
    }
    return false;
}

// systemd-resolved rejects the whole SetLinkDomains call if one name is not a valid DNS name
static bool is_valid_routing_domain(const char *name) {
    size_t total = strlen(name);
    if (total == 0 || total > 253) {
        return false;
    }

    size_t label = 0;
    for (const char *p = name; ; p++) {
        // escapes and control characters would need the DNS escaping rules that systemd-resolved applies
        if (*p == '\\' || (*p != '\0' && (unsigned char) *p <= ' ') || (unsigned char) *p == 0x7f) {
            return false;
        }
        if (*p == '.' || *p == '\0') {
            if (label == 0 || label > 63) {
                return false;
            }
            if (*p == '\0') {
                return true;
            }
            label = 0;
        } else {
            label++;
        }
    }
}

/*
 * Set the link's routing-only domains; with `wildcard` also "~.", which makes the link compete for all other names.
 * Returns 0, -E2BIG if there are more than `limit` names, -ENOSPC if systemd-resolved rejected them as too many,
 * or another negative error.
 */
static int set_link_domains(sd_bus *bus, const char *tun, int32_t ifindex, const char *const *domains, bool wildcard,
                            size_t limit) {
    _cleanup_(sd_bus_message_unrefp_f) sd_bus_message *m = NULL;
    _cleanup_(sd_bus_error_free_wrapper) sd_bus_error error = SD_BUS_ERROR_NULL;
    int r;
    size_t count = 0;

    for (const char *const *d = domains; d && *d; d++) {
        if (is_valid_routing_domain(*d)) count++;
    }
    if (count + (wildcard ? 1 : 0) > limit) {
        ZITI_LOG(DEBUG, "%zu names exceed the limit of %zu routing domains on interface: %s", count, limit, tun);
        return -E2BIG;
    }
    count = 0;

    r = sd_bus_message_new_method_call_f(bus, &m, RESOLVED_DBUS_NAME, RESOLVED_DBUS_PATH,
                                         RESOLVED_DBUS_MANAGER_INTERFACE, "SetLinkDomains");
    if (r >= 0) r = sd_bus_message_append_f(m, "i", ifindex);
    if (r >= 0) r = sd_bus_message_open_container_f(m, SD_BUS_TYPE_ARRAY, "(sb)");
    for (const char *const *d = domains; r >= 0 && d && *d; d++) {
        if (!is_valid_routing_domain(*d)) {
            ZITI_LOG(WARN, "not adding invalid routing domain[%s] on interface: %s", *d, tun);
            continue;
        }
        r = sd_bus_message_append_f(m, "(sb)", *d, 1);
        count++;
    }
    if (r >= 0 && wildcard) r = sd_bus_message_append_f(m, "(sb)", ".", 1);
    if (r >= 0) r = sd_bus_message_close_container_f(m);
    if (r < 0) {
        ZITI_LOG(ERROR, "Failure composing DBus message: %s", strerror(-r));
        return r;
    }

    r = sd_bus_call_f(bus, m, 0, &error, NULL);
    if (r < 0) {
        if (r == -E2BIG || sd_bus_error_has_name_f(&error, SD_BUS_ERROR_LIMITS_EXCEEDED)) {
            ZITI_LOG(DEBUG, "systemd-resolved rejected %zu routing domains on interface: %s", count, tun);
            return -ENOSPC;
        }
        ZITI_LOG(ERROR, "Failure calling method: SetLinkDomains for link: (%s): (%s, %s)", tun, error.name, error.message);
        return r;
    }

    ZITI_LOG(INFO, "Set %zu routing domains%s on interface: %s", count, wildcard ? " and wildcard routing domain" : "", tun);
    return 0;
}

/*
 * The domains that systemd-resolved routes to other links, and global domains, lower case without the trailing
 * dot ("." for "~."). Returns a NULL-terminated list owned by the caller, or NULL on error.
 */
static char **get_other_link_domains(sd_bus *bus, int32_t own_ifindex) {
    _cleanup_(sd_bus_message_unrefp_f) sd_bus_message *reply = NULL;
    _cleanup_(sd_bus_error_free_wrapper) sd_bus_error error = SD_BUS_ERROR_NULL;

    int r = sd_bus_get_property_f(bus, RESOLVED_DBUS_NAME, RESOLVED_DBUS_PATH, RESOLVED_DBUS_MANAGER_INTERFACE,
                                  "Domains", &error, &reply, "a(isb)");
    if (r < 0) {
        ZITI_LOG(ERROR, "Could not retrieve systemd-resolved domains: (%s, %s)", error.name, error.message);
        return NULL;
    }
    r = sd_bus_message_enter_container_f(reply, SD_BUS_TYPE_ARRAY, "(isb)");
    if (r < 0) {
        ZITI_LOG(ERROR, "Failure reading DBus message: %s", strerror(-r));
        return NULL;
    }

    size_t count = 0, capacity = 16;
    char **names = calloc(capacity + 1, sizeof(char *));
    if (names == NULL) {
        return NULL;
    }
    int32_t ifindex;
    const char *name;
    int routing_only;
    // all members must be read before the container can be exited
    while ((r = sd_bus_message_read_f(reply, "(isb)", &ifindex, &name, &routing_only)) > 0) {
        if (ifindex == own_ifindex || name == NULL || *name == '\0') {
            continue;
        }
        if (count == capacity) {
            capacity *= 2;
            char **grown = realloc(names, (capacity + 1) * sizeof(char *));
            if (grown == NULL) {
                r = -ENOMEM;
                break;
            }
            names = grown;
        }
        char *copy = strdup(name);
        if (copy == NULL) {
            r = -ENOMEM;
            break;
        }
        size_t len = strlen(copy);
        if (len > 1 && copy[len - 1] == '.') copy[len - 1] = '\0';
        for (char *c = copy; *c; c++) *c = (char) tolower((unsigned char) *c);
        names[count++] = copy;
        names[count] = NULL;
    }
    if (r >= 0) {
        r = sd_bus_message_exit_container_f(reply);
    }
    if (r < 0) {
        ZITI_LOG(ERROR, "Failure reading DBus message: %s", strerror(-r));
        free_names(names);
        return NULL;
    }
    return names;
}

int systemd_resolved_wildcard_mismatch(int32_t own_ifindex) {
    if (own_ifindex <= 0) return -ENODEV;
    _cleanup_(sd_bus_flush_close_unrefp_f) sd_bus *bus = NULL;
    _cleanup_(sd_bus_message_unrefp_f) sd_bus_message *reply = NULL;

    int r = sd_bus_open_system_f(&bus);
    if (r < 0) return r;
    r = sd_bus_get_property_f(bus, RESOLVED_DBUS_NAME, RESOLVED_DBUS_PATH, RESOLVED_DBUS_MANAGER_INTERFACE,
                              "Domains", NULL, &reply, "a(isb)");
    if (r < 0) return r;
    r = sd_bus_message_enter_container_f(reply, SD_BUS_TYPE_ARRAY, "(isb)");
    if (r < 0) return r;

    bool own_wildcard = false, other_wildcard = false;
    int32_t ifindex;
    const char *name;
    int routing_only;
    while ((r = sd_bus_message_read_f(reply, "(isb)", &ifindex, &name, &routing_only)) > 0) {
        if (name != NULL && strcmp(name, ".") == 0 && routing_only) {
            if (ifindex == own_ifindex) own_wildcard = true;
            else other_wildcard = true;
        }
    }
    if (r < 0) return r;
    r = sd_bus_message_exit_container_f(reply);
    if (r < 0) return r;
    return own_wildcard != other_wildcard;
}

void dns_update_systemd_resolved(const char *tun, unsigned int ifindex, const char *addr, char **domains, bool default_route) {
    int r;
    struct in_addr inaddr;

    _cleanup_(sd_bus_flush_close_unrefp_f) sd_bus *bus = NULL;

    // dbus 'ay' encodes 'array of bytes'
    unsigned char ay[4];

    r = inet_pton(AF_INET, addr, &inaddr);

    if (r != 1) {
        ZITI_LOG(ERROR, "Failed to translate DNS address. Received: %s", addr);
        return;
    } else {
        sscanf(addr, "%hhu.%hhu.%hhu.%hhu", &ay[0], &ay[1], &ay[2], &ay[3]);
    }

    r = sd_bus_open_system_f(&bus);
    if (r < 0) {
        ZITI_LOG(ERROR, "Could not connect to system DBus: %s", strerror(-r));
        return;
    }

    RET_ON_FAIL(set_systemd_resolved_link_setting(bus, tun, "SetLinkLLMNR", "is", ifindex, "no"));
    RET_ON_FAIL(set_systemd_resolved_link_setting(bus, tun, "SetLinkMulticastDNS", "is", ifindex, "no"));
    RET_ON_FAIL(set_systemd_resolved_link_setting(bus, tun, "SetLinkDNSOverTLS", "is", ifindex, "no"));
    RET_ON_FAIL(set_systemd_resolved_link_setting(bus, tun, "SetLinkDNSSEC", "is", ifindex, "no"));
    RET_ON_FAIL(set_systemd_resolved_link_setting(bus, tun, "SetLinkDNS", "ia(iay)", ifindex, 1, AF_INET, 4, ay[0], ay[1], ay[2], ay[3]));

    char **others = get_other_link_domains(bus, (int32_t) ifindex);
    // with an upstream, the ziti resolver can answer any name, so the link is a default route. a link that claims
    // all names with "~." outranks default routes, so the link must claim "~." too when another link does
    bool wildcard = default_route && contains_name(others, ".");
    size_t extra = wildcard ? 1 : 0;

    size_t count = 0;
    while (domains && domains[count]) count++;

    for (size_t limit = RESOLVED_LINK_DOMAINS_MAX; ; limit /= 2) {
        if (count + extra > limit) {
            // merge names into parent domains, but not into domains that other links route, which would take them over
            count = ziti_dns_compact_domains(domains, limit - extra, (const char *const *) others);
        }
        r = set_link_domains(bus, tun, (int32_t) ifindex, (const char *const *) domains, wildcard, limit);
        if (r == -ENOSPC) {
            // systemd-resolved counts the link's current domains together with the new ones, and removes them all
            // when it rejects the call, so the same list fits now unless this version accepts fewer per link
            r = set_link_domains(bus, tun, (int32_t) ifindex, (const char *const *) domains, wildcard, limit);
        }
        if (r != -ENOSPC || limit / 2 < RESOLVED_LINK_DOMAINS_MIN) {
            break;
        }
    }

    if (r != 0) {
        // a link with neither routing domains nor default route would never be queried: fall back to the ziti
        // resolver being a default route, as before routing domains were used
        ZITI_LOG(WARN, "Could not set routing domains, using the ziti resolver as a default DNS route on interface: %s", tun);
        bool other_wildcard = contains_name(others, ".");
        r = set_link_domains(bus, tun, (int32_t) ifindex, NULL, other_wildcard, 1);
        if (r == -ENOSPC) {
            r = set_link_domains(bus, tun, (int32_t) ifindex, NULL, other_wildcard, 1);
        }
        default_route = true;
    }
    free_names(others);
    if (r != 0) {
        return;
    }
    // set after the domains, so the link is never left with neither
    RET_ON_FAIL(set_systemd_resolved_link_setting(bus, tun, "SetLinkDefaultRoute", "ib", ifindex, default_route));

    sd_bus_run_command(bus, RESOLVED_DBUS_NAME, RESOLVED_DBUS_PATH, RESOLVED_DBUS_MANAGER_INTERFACE, "FlushCaches");
    sd_bus_run_command(bus, RESOLVED_DBUS_NAME, RESOLVED_DBUS_PATH, RESOLVED_DBUS_MANAGER_INTERFACE, "ResetServerFeatures");
}

// links that only route specific domains (e.g. a VPN) are not used for arbitrary names
static bool is_default_route_link(sd_bus *bus, int32_t ifindex) {
    _cleanup_(sd_bus_message_unrefp_f) sd_bus_message *link = NULL;
    _cleanup_(sd_bus_message_unrefp_f) sd_bus_message *reply = NULL;
    const char *path = NULL;
    int default_route = 1;

    int r = sd_bus_call_method_f(bus, RESOLVED_DBUS_NAME, RESOLVED_DBUS_PATH, RESOLVED_DBUS_MANAGER_INTERFACE,
                                 "GetLink", NULL, &link, "i", ifindex);
    if (r >= 0) r = sd_bus_message_read_f(link, "o", &path);
    if (r >= 0) r = sd_bus_get_property_f(bus, RESOLVED_DBUS_NAME, path, RESOLVED_DBUS_LINK_INTERFACE,
                                          "DefaultRoute", NULL, &reply, "b");
    if (r >= 0) r = sd_bus_message_read_f(reply, "b", &default_route);
    if (r < 0) {
        // DefaultRoute is not available before systemd 240, where every link with DNS servers is a default route
        ZITI_LOG(DEBUG, "could not determine DefaultRoute of link[%d]: %s", ifindex, strerror(-r));
        return true;
    }
    return default_route != 0;
}

static bool is_loopback_server(const struct sockaddr_storage *ss) {
    if (ss->ss_family == AF_INET) {
        return (ntohl(((const struct sockaddr_in *) ss)->sin_addr.s_addr) >> 24) == 127;
    }
    const struct in6_addr *a = &((const struct sockaddr_in6 *) ss)->sin6_addr;
    return IN6_IS_ADDR_LOOPBACK(a) || (IN6_IS_ADDR_V4MAPPED(a) && a->s6_addr[12] == 127);
}

// the servers systemd-resolved knows about are servers it queries itself, so they are safe to forward to.
// only addresses that cannot be sent to are skipped
static bool is_usable_server(const struct sockaddr_storage *ss) {
    if (ss->ss_family == AF_INET) {
        return ((const struct sockaddr_in *) ss)->sin_addr.s_addr != INADDR_ANY;
    }
    const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *) ss;
    return !IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr) &&
           // link-local servers need the scope of the link they were learned on
           (!IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr) || sin6->sin6_scope_id != 0);
}

/*
 * Read the servers of a Manager property ("DNS" or "FallbackDNS") that systemd-resolved uses for names without a
 * routing domain. `configured` counts them before the address filters, so the caller knows whether resolved has
 * such servers at all. The "Ex" variant of the property (systemd 246+) includes the port; without it, 53 is used.
 */
static int read_dns_servers(sd_bus *bus, const char *property, int32_t exclude_ifindex, uint32_t exclude_ip,
                            struct sockaddr_storage *addrs, size_t max, size_t *configured) {
    _cleanup_(sd_bus_message_unrefp_f) sd_bus_message *reply = NULL;
    _cleanup_(sd_bus_error_free_wrapper) sd_bus_error error = SD_BUS_ERROR_NULL;
    int r;

    char property_ex[32];
    snprintf(property_ex, sizeof(property_ex), "%sEx", property);
    bool ex = true;
    r = sd_bus_get_property_f(bus, RESOLVED_DBUS_NAME, RESOLVED_DBUS_PATH, RESOLVED_DBUS_MANAGER_INTERFACE,
                              property_ex, &error, &reply, "a(iiayqs)");
    if (r < 0) {
        ZITI_LOG(DEBUG, "systemd-resolved %s is not available, using %s: (%s, %s)", property_ex, property,
                 error.name, error.message);
        sd_bus_error_free_f(&error);
        reply = sd_bus_message_unref_f(reply);
        ex = false;
        r = sd_bus_get_property_f(bus, RESOLVED_DBUS_NAME, RESOLVED_DBUS_PATH, RESOLVED_DBUS_MANAGER_INTERFACE,
                                  property, &error, &reply, "a(iiay)");
    }
    if (r < 0) {
        ZITI_LOG(ERROR, "Could not retrieve systemd-resolved %s servers: (%s, %s)", property, error.name, error.message);
        return r;
    }

    r = sd_bus_message_enter_container_f(reply, SD_BUS_TYPE_ARRAY, ex ? "(iiayqs)" : "(iiay)");
    if (r < 0) {
        ZITI_LOG(ERROR, "Failure reading DBus message: %s", strerror(-r));
        return r;
    }

    size_t count = 0;
    // all members must be read before the container can be exited, so keep going after max is reached
    while ((r = sd_bus_message_enter_container_f(reply, SD_BUS_TYPE_STRUCT, ex ? "iiayqs" : "iiay")) > 0) {
        int32_t ifindex, family;
        const void *data = NULL;
        size_t len = 0;
        uint16_t port = 0;
        const char *server_name = NULL;

        r = sd_bus_message_read_f(reply, "ii", &ifindex, &family);
        if (r >= 0) r = sd_bus_message_read_array_f(reply, 'y', &data, &len);
        if (r >= 0 && ex) r = sd_bus_message_read_f(reply, "qs", &port, &server_name);
        if (r >= 0) r = sd_bus_message_exit_container_f(reply);
        if (r < 0) {
            ZITI_LOG(ERROR, "Failure reading DBus message: %s", strerror(-r));
            return r;
        }
        if (port == 0) port = 53;

        if (ifindex == exclude_ifindex) {
            continue;
        }

        struct sockaddr_storage ss = {0};
        if (family == AF_INET && len == 4) {
            struct sockaddr_in *sin = (struct sockaddr_in *) &ss;
            sin->sin_family = AF_INET;
            sin->sin_port = htons(port);
            memcpy(&sin->sin_addr, data, len);
        } else if (family == AF_INET6 && len == 16) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &ss;
            sin6->sin6_family = AF_INET6;
            sin6->sin6_port = htons(port);
            memcpy(&sin6->sin6_addr, data, len);
            if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) {
                sin6->sin6_scope_id = ifindex;
            }
        } else {
            ZITI_LOG(DEBUG, "skipping %s server of link[%d]: family %d, %zu address bytes", property, ifindex, family, len);
            continue;
        }

        char host[INET6_ADDRSTRLEN] = "";
        uv_ip_name((const struct sockaddr *) &ss, host, sizeof(host));

        // ifindex 0 is a global server, which systemd-resolved uses for any name. a loopback server (e.g. a local
        // dnsmasq) is reported under the loopback interface whichever link or the global configuration it belongs to,
        // so its link cannot be checked; systemd-resolved uses it like any other configured server
        if (ifindex != 0 && !is_loopback_server(&ss) && !is_default_route_link(bus, ifindex)) {
            ZITI_LOG(DEBUG, "skipping %s server %s of link[%d]: not a default route", property, host, ifindex);
            continue;
        }
        if (configured) {
            (*configured)++;
        }
        if (count >= max) {
            continue;
        }

        if (!is_usable_server(&ss)) {
            ZITI_LOG(DEBUG, "skipping %s server %s of link[%d]: not reachable", property, host, ifindex);
            continue;
        }
        // the ziti resolver itself may be configured elsewhere, e.g. as a global server
        if (ss.ss_family == AF_INET && ((struct sockaddr_in *) &ss)->sin_addr.s_addr == exclude_ip) {
            ZITI_LOG(DEBUG, "skipping %s server %s of link[%d]: the ziti resolver", property, host, ifindex);
            continue;
        }
        ZITI_LOG(DEBUG, "%s server %s:%u of link[%d]", property, host, port, ifindex);

        bool dup = false;
        for (size_t i = 0; i < count && !dup; i++) {
            dup = memcmp(&addrs[i], &ss, sizeof(ss)) == 0;
        }
        if (!dup) {
            addrs[count++] = ss;
        }
    }
    if (r < 0) {
        ZITI_LOG(ERROR, "Failure reading DBus message: %s", strerror(-r));
        return r;
    }

    r = sd_bus_message_exit_container_f(reply);
    if (r < 0) {
        ZITI_LOG(ERROR, "Failure exiting DBus message container: %s", strerror(-r));
        return r;
    }

    return (int) count;
}

int systemd_resolved_get_dns_servers(int32_t exclude_ifindex, uint32_t exclude_ip, struct sockaddr_storage *addrs, size_t max) {
    _cleanup_(sd_bus_flush_close_unrefp_f) sd_bus *bus = NULL;

    if (!libsystemd_load()) {
        return -ENOTSUP;
    }

    int r = sd_bus_open_system_f(&bus);
    if (r < 0) {
        ZITI_LOG(ERROR, "Could not connect to system DBus: %s", strerror(-r));
        return r;
    }

    size_t configured = 0;
    r = read_dns_servers(bus, "DNS", exclude_ifindex, exclude_ip, addrs, max, &configured);
    if (r == 0 && configured == 0) {
        // like systemd-resolved, use its fallback servers only when there are no servers configured at all
        r = read_dns_servers(bus, "FallbackDNS", exclude_ifindex, exclude_ip, addrs, max, NULL);
        if (r < 0) {
            r = 0;
        }
    }
    return r;
}

#endif // EXCLUDE_LIBSYSTEMD_RESOLVER
