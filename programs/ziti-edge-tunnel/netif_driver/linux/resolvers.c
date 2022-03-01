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

#include <net/if.h>
#include <stdbool.h>
#include <stdlib.h>
#ifndef EXCLUDE_LIBSYSTEMD_RESOLVER
#include <systemd/sd-bus-protocol.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-bus.h>
#endif

#include <ziti/ziti_log.h>
#include <uv.h>

#include "utils.h"

#ifndef EXCLUDE_LIBSYSTEMD_RESOLVER
#ifndef RESOLVED_DBUS_NAME
#define RESOLVED_DBUS_NAME "org.freedesktop.resolve1"
#endif

#ifndef RESOLVED_DBUS_PATH
#define RESOLVED_DBUS_PATH "/org/freedesktop/resolve1"
#endif

#ifndef RESOLVED_DBUS_MANAGER_INTERFACE
#define RESOLVED_DBUS_MANAGER_INTERFACE "org.freedesktop.resolve1.Manager"
#endif

#define _cleanup_(f) __attribute__((cleanup(f)))
#define TRY_DL(dl_func) do{if ((dl_func) != 0) goto dl_error;} while(0)

static int detect_systemd_resolved_acquired_name(sd_bus *bus);
static int detect_systemd_resolved_routing_domain_wildcard(sd_bus *bus, int32_t ifindex);
static bool set_systemd_resolved_link_dns(sd_bus *bus, int32_t ifindex, const char* tun, const char* dns_addr);
static bool set_systemd_resolved_link_dnssec(sd_bus *bus, int32_t ifindex, const char*tun);
static bool set_systemd_resolved_link_domain(sd_bus *bus, int32_t ifindex, const char* tun);

// libsystemd prototypes
static uv_once_t guard;
static uv_lib_t libsystemd_h;
static bool libsystemd_dl_success = true;
static int (*sd_booted_f)(void);
static int (*sd_bus_call_f)(sd_bus *bus, sd_bus_message *m, uint64_t usec, sd_bus_error *ret_error, sd_bus_message **reply);
static int (*sd_bus_call_method_f)(sd_bus *bus, const char *destination, const char *path, const char *interface, const char *member, sd_bus_error *ret_error, sd_bus_message **reply, const char *types, ...);
static void (*sd_bus_error_free_f)(sd_bus_error *e);
static sd_bus *(*sd_bus_flush_close_unref_f)(sd_bus *bus);
static int (*sd_bus_get_property_f)(sd_bus *bus, const char *destination, const char *path, const char *interface, const char *member, sd_bus_error *ret_error, sd_bus_message **reply, const char *type);
static int (*sd_bus_is_bus_client_f)(sd_bus *bus);
static int (*sd_bus_message_append_f)(sd_bus_message *m, const char *types, ...);
static int (*sd_bus_message_append_array_f)(sd_bus_message *m, char type, void *ptr, size_t size);
static int (*sd_bus_message_close_container_f)(sd_bus_message *m);
static int (*sd_bus_message_enter_container_f)(sd_bus_message *m, char type, const char *contents);
static int (*sd_bus_message_exit_container_f)(sd_bus_message *m);
static int (*sd_bus_message_new_method_call_f)(sd_bus *bus, sd_bus_message **m, const char *destination, const char *path, const char *interface, const char *member);
static int (*sd_bus_message_open_container_f)(sd_bus_message *m, char type, const char *contents);
static int (*sd_bus_message_read_f)(sd_bus_message *m, const char *types, ...);
static int (*sd_bus_message_read_strv_f)(sd_bus_message *m, char ***l);
static sd_bus_message *(*sd_bus_message_unref_f)(sd_bus_message *m);
static int (*sd_bus_open_system_f)(sd_bus **bus);

static void init_libsystemd() {
    ZITI_LOG(INFO, "Initializing libsystemd");
    TRY_DL(uv_dlopen("libsystemd.so.0", &libsystemd_h));
    TRY_DL(uv_dlsym(&libsystemd_h, "sd_booted", (void **) &sd_booted_f));
    TRY_DL(uv_dlsym(&libsystemd_h, "sd_bus_call", (void **) &sd_bus_call_f));
    TRY_DL(uv_dlsym(&libsystemd_h, "sd_bus_call_method", (void **) &sd_bus_call_method_f));
    TRY_DL(uv_dlsym(&libsystemd_h, "sd_bus_error_free", (void **) &sd_bus_error_free_f));
    TRY_DL(uv_dlsym(&libsystemd_h, "sd_bus_flush_close_unref", (void **) &sd_bus_flush_close_unref_f));
    TRY_DL(uv_dlsym(&libsystemd_h, "sd_bus_get_property", (void **) &sd_bus_get_property_f));
    TRY_DL(uv_dlsym(&libsystemd_h, "sd_bus_is_bus_client", (void **) &sd_bus_is_bus_client_f));
    TRY_DL(uv_dlsym(&libsystemd_h, "sd_bus_message_append", (void **) &sd_bus_message_append_f));
    TRY_DL(uv_dlsym(&libsystemd_h, "sd_bus_message_append_array", (void **) &sd_bus_message_append_array_f));
    TRY_DL(uv_dlsym(&libsystemd_h, "sd_bus_message_close_container", (void **) &sd_bus_message_close_container_f));
    TRY_DL(uv_dlsym(&libsystemd_h, "sd_bus_message_enter_container", (void **) &sd_bus_message_enter_container_f));
    TRY_DL(uv_dlsym(&libsystemd_h, "sd_bus_message_exit_container", (void **) &sd_bus_message_exit_container_f));
    TRY_DL(uv_dlsym(&libsystemd_h, "sd_bus_message_new_method_call", (void **) &sd_bus_message_new_method_call_f));
    TRY_DL(uv_dlsym(&libsystemd_h, "sd_bus_message_open_container", (void **) &sd_bus_message_open_container_f));
    TRY_DL(uv_dlsym(&libsystemd_h, "sd_bus_message_read", (void **) &sd_bus_message_read_f));
    TRY_DL(uv_dlsym(&libsystemd_h, "sd_bus_message_read_strv", (void **) &sd_bus_message_read_strv_f));
    TRY_DL(uv_dlsym(&libsystemd_h, "sd_bus_message_unref", (void **) &sd_bus_message_unref_f));
    TRY_DL(uv_dlsym(&libsystemd_h, "sd_bus_open_system", (void **) &sd_bus_open_system_f));

    goto done;

    dl_error:
    ZITI_LOG(WARN, "Failure during dynamic loading function: %s", uv_dlerror(&libsystemd_h));
    libsystemd_dl_success=false;

    done:
    if (libsystemd_dl_success) {
        ZITI_LOG(DEBUG, "Dynamically loaded libsystemd");
    }
    return;
}

// Added to work around proprocessor time symbols missing
static void sd_bus_flush_close_unrefp_f(sd_bus **p) {
    if (*p) {
        sd_bus_flush_close_unref_f(*p);
    }
}

// Added to work around proprocessor time symbols missing
static void sd_bus_message_unrefp_f(sd_bus_message **p) {
    if (*p) {
        sd_bus_message_unref_f(*p);
    }
}

// Added to work around proprocessor time symbols missing
static void sd_bus_error_free_wrapper(sd_bus_error *e) {
    sd_bus_error_free_f(e);
}

static int detect_systemd_resolved_acquired_name(sd_bus *bus) {
    int r;
    _cleanup_(sd_bus_message_unrefp_f) sd_bus_message *reply = NULL;
    _cleanup_(sd_bus_error_free_wrapper) sd_bus_error error = SD_BUS_ERROR_NULL;
    char** acquired = NULL;

    r = sd_bus_call_method_f(
            bus,
            "org.freedesktop.DBus",
            "/org/freedesktop/DBUS",
            "org.freedesktop.DBus",
            "ListNames",
            &error,
            &reply,
            NULL);

    if (r < 0) {
        ZITI_LOG(ERROR, "Could not retreive DBus bus names: (%s, %s)", error.name, error.message);
        return r;
    }

    r = sd_bus_message_read_strv_f(reply, &acquired);
    if (r < 0) {
        ZITI_LOG(ERROR, "Could not read DBus reply: %s", strerror(-r));
        return r;
    }

    reply = sd_bus_message_unref_f(reply);

    size_t i;
    int found = 1;

    for (i=0; acquired[i] != NULL; i++) {
        if (strcmp(acquired[i], RESOLVED_DBUS_NAME) == 0) {
            ZITI_LOG(DEBUG, "systemd-resolve DBus name found: %s", acquired[i]);
        found = 0;
        break;
        }
    }

    if (acquired != NULL) {
        for (i=0; acquired[i] != NULL; i++) {
            free(acquired[i]);
        }
        free(acquired);
    }

    return found;
}

static int detect_systemd_resolved_routing_domain_wildcard(sd_bus *bus, int32_t ifindex) {
    _cleanup_(sd_bus_message_unrefp_f) sd_bus_message *reply = NULL;
    _cleanup_(sd_bus_error_free_wrapper) sd_bus_error error = SD_BUS_ERROR_NULL;

    int r;

    r = sd_bus_get_property_f(
            bus,
            RESOLVED_DBUS_NAME,
            RESOLVED_DBUS_PATH,
            RESOLVED_DBUS_MANAGER_INTERFACE,
            "Domains",
            &error,
            &reply,
            "a(isb)"
            );
    if (r < 0) {
        ZITI_LOG(ERROR, "Could not retrieve systemd-resolved domains: (%s, %s)", error.name, error.message);
        return r;
    }

    r = sd_bus_message_enter_container_f(reply, SD_BUS_TYPE_ARRAY, "(isb)");
    if (r < 0) {
        ZITI_LOG(ERROR, "Failure composing DBus message: (%s, %s)", error.name, error.message);
        return r;
    }

    struct s_domain {
        int32_t ifindex;
        char * name;
        int is_routing_only;
    };

    struct s_domain domain;

    int routing_only_wildcard_set = 1;

    while ((r = sd_bus_message_read_f(reply, "(isb)", &domain.ifindex, &domain.name, &domain.is_routing_only)) > 0){
        if ((domain.ifindex != ifindex) &&
            (strcmp(domain.name, ".") == 0) &&
            (domain.is_routing_only == 1)) {
            ZITI_LOG(DEBUG, "systemd-resolved routing only domain wildcard found");
            routing_only_wildcard_set = 0;
            break;
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

    return routing_only_wildcard_set;
}

static bool set_systemd_resolved_link_domain(sd_bus *bus, int32_t ifindex, const char* tun) {
    _cleanup_(sd_bus_message_unrefp_f) sd_bus_message *reply = NULL;
    _cleanup_(sd_bus_error_free_wrapper) sd_bus_error error = SD_BUS_ERROR_NULL;

    int r;

    r = sd_bus_call_method_f(
            bus,
            RESOLVED_DBUS_NAME,
            RESOLVED_DBUS_PATH,
            RESOLVED_DBUS_MANAGER_INTERFACE,
            "SetLinkDomains",
            &error,
            &reply,
            "ia(sb)",
            ifindex,
            1,
            ".",
            true);

    if (r < 0) {
        ZITI_LOG(ERROR, "Could not set link domain (%s): (%s, %s)", tun, error.name, error.message);
        return false;
    }

    return true;
}

static bool set_systemd_resolved_link_dnssec(sd_bus *bus, int32_t ifindex, const char*tun) {
    _cleanup_(sd_bus_message_unrefp_f) sd_bus_message *reply = NULL;
    _cleanup_(sd_bus_error_free_wrapper) sd_bus_error error = SD_BUS_ERROR_NULL;

    int r;

    r = sd_bus_call_method_f(
            bus,
            RESOLVED_DBUS_NAME,
            RESOLVED_DBUS_PATH,
            RESOLVED_DBUS_MANAGER_INTERFACE,
            "SetLinkDNSSEC",
            &error,
            &reply,
            "is",
            ifindex,
            "no");
    if (r < 0) {
        ZITI_LOG(ERROR, "Failed to set link DNSSEC property (%s): (%s, %s)", tun, error.name, error.message);
        return false;
    }

    return true;
}

static bool set_systemd_resolved_link_dns(sd_bus *bus, int32_t ifindex, const char* tun, const char* dns_addr) {
    _cleanup_(sd_bus_message_unrefp_f) sd_bus_message *message = NULL;
    _cleanup_(sd_bus_message_unrefp_f) sd_bus_message *reply = NULL;
    _cleanup_(sd_bus_error_free_wrapper) sd_bus_error error = SD_BUS_ERROR_NULL;

    int r;

    struct in_addr inaddr;
    r = inet_pton(AF_INET, dns_addr, &inaddr);
    if (r != 1) {
        ZITI_LOG(ERROR, "Failed to translate dns address");
        return false;
    }

    r = sd_bus_message_new_method_call_f(
        bus,
        &message,
        RESOLVED_DBUS_NAME,
        RESOLVED_DBUS_PATH,
        RESOLVED_DBUS_MANAGER_INTERFACE,
        "SetLinkDNS");

    if (r < 0) {
        ZITI_LOG(ERROR, "Failed to create bus message: %s", strerror(-r));
        return false;
    }

    sd_bus_message_append_f(message, "i", ifindex);
    sd_bus_message_open_container_f(message, SD_BUS_TYPE_ARRAY, "(iay)");
    sd_bus_message_open_container_f(message, SD_BUS_TYPE_STRUCT, "iay");
    sd_bus_message_append_f(message, "i", AF_INET);
    sd_bus_message_append_array_f(message, SD_BUS_TYPE_BYTE, &inaddr, sizeof(inaddr));
    sd_bus_message_close_container_f(message);
    sd_bus_message_close_container_f(message);

    r = sd_bus_call_f(bus, message, 0, &error, &reply);
    if (r < 0) {
        ZITI_LOG(ERROR, "Could not set link DNS (%s). DBus error: (%s, %s)", tun, error.name,error.message);
        return false;
    }

    return true;
}

bool try_systemd_resolved(void) {
    uv_once(&guard, init_libsystemd);
    if (!libsystemd_dl_success) {
        return false;
    }

    _cleanup_(sd_bus_flush_close_unrefp_f) sd_bus *bus = NULL;

    int r;

    if (sd_booted_f() > 0) {
        ZITI_LOG(DEBUG, "Detected systemd is init system");
    } else {
        ZITI_LOG(DEBUG, "Could not detect systemd init system");
    }

    r = sd_bus_open_system_f(&bus);
    if ((r >= 0) && (sd_bus_is_bus_client_f(bus) > 0)) {
        ZITI_LOG(DEBUG, "Connected to system DBus");
        r = detect_systemd_resolved_acquired_name(bus);
        if (r < 0) {
            ZITI_LOG(ERROR, "Error in systemd-resolved resolver detection. Falling back to legacy resolvers...");
            return false;
        }
        if (r == 0) {
            ZITI_LOG(INFO, "systemd-resolved selected as dns resolver manager");
            return true;
        }
    } else {
        ZITI_LOG(DEBUG, "Could not create system DBus client");
    }

    return false;
}

void dns_update_systemd_resolved(const char* tun, const char* addr) {
    int r;
    int ifindex;

    _cleanup_(sd_bus_flush_close_unrefp_f) sd_bus *bus = NULL;

    r = sd_bus_open_system_f(&bus);
    if (r < 0) {
        ZITI_LOG(ERROR, "Could not connect to system DBus: %s", strerror(-r));
        return;
    }

    if ((ifindex = if_nametoindex(tun)) == 0) {
        ZITI_LOG(ERROR, "Could not find interface index for: %s", tun);
        return;
    }

    if (!set_systemd_resolved_link_dnssec(bus, ifindex, tun)) {
        ZITI_LOG(ERROR, "Could not set DNSSEC for link: %s", tun);
        return;
    }

    if (!set_systemd_resolved_link_dns(bus, ifindex, tun, addr)) {
        ZITI_LOG(ERROR, "Could not set dns for link: %s", tun);
        return;
    }

    r = detect_systemd_resolved_routing_domain_wildcard(bus, ifindex);
    if (r < 0) {
        ZITI_LOG(ERROR, "Error detecting systemd-resolved domain configuration: %s", strerror(-r));
        return;
    }

    if (r == 0) {
        ZITI_LOG(INFO, "Setting wilcard routing only domain on interface: %s", tun);
        if (!set_systemd_resolved_link_domain(bus, ifindex, tun)) {
            ZITI_LOG(ERROR, "Could not set domain for link: %s", tun);
            return;
        }
    }
}
#endif

void dns_update_resolvconf(const char* tun, const char* addr) {
    run_command("echo 'nameserver %s' | resolvconf -a %s", addr, tun);
}

void dns_update_etc_resolv(const char* tun, const char* addr) {
    if (run_command("grep -q '^nameserver %s' /etc/resolv.conf", addr) != 0){
        run_command("sed -z -i 's/nameserver/nameserver %s\\nnameserver/' /etc/resolv.conf", addr);
    }
}
