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

#include <libgen.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/acl.h>
#include <acl/libacl.h>

#ifndef EXCLUDE_LIBSYSTEMD_RESOLVER
#include <net/if.h>
#include <stdarg.h>
#include <systemd/sd-bus-protocol.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-bus.h>
#endif

#include <ziti/ziti_log.h>
#include <uv.h>

#include "resolvers.h"
#include "utils.h"

#define _cleanup_(f) __attribute__((cleanup(f)))
#ifndef EXCLUDE_LIBSYSTEMD_RESOLVER
#define TRY_DL(dl_func) do{if ((dl_func) != 0) goto dl_error;} while(0)
#define RET_ON_FAIL(bool_func) do{if (!(bool_func)) return;} while(0)

static int sd_bus_is_acquired_name(sd_bus *bus, const char *bus_name);
static int detect_systemd_resolved_routing_domain_wildcard(sd_bus *bus, int32_t ifindex);
static bool set_systemd_resolved_link_setting(sd_bus *bus, const char *tun, const char *method, const char *method_type, ...);

// libsystemd prototypes
static uv_once_t guard;
static uv_lib_t libsystemd_h;
static bool libsystemd_dl_success = true;
static int (*sd_booted_f)(void);
static int (*sd_bus_call_f)(sd_bus *bus, sd_bus_message *m, uint64_t usec, sd_bus_error *ret_error, sd_bus_message **reply);
static int (*sd_bus_call_method_f)(sd_bus *bus, const char *destination, const char *path, const char *interface, const char *member, sd_bus_error *ret_error, sd_bus_message **reply, const char *types, ...);
static void (*sd_bus_error_free_f)(sd_bus_error *e);
static int (*sd_bus_error_has_name_f)(const sd_bus_error *e, const char *name);
static int (*sd_bus_error_set_errno_f)(sd_bus_error *e, int error);
static sd_bus *(*sd_bus_flush_close_unref_f)(sd_bus *bus);
static int (*sd_bus_get_property_f)(sd_bus *bus, const char *destination, const char *path, const char *interface, const char *member, sd_bus_error *ret_error, sd_bus_message **reply, const char *type);
static int (*sd_bus_is_bus_client_f)(sd_bus *bus);
static int (*sd_bus_message_appendv_f)(sd_bus_message *m, const char *types, va_list ap);
static int (*sd_bus_message_enter_container_f)(sd_bus_message *m, char type, const char *contents);
static int (*sd_bus_message_exit_container_f)(sd_bus_message *m);
static int (*sd_bus_message_new_method_call_f)(sd_bus *bus, sd_bus_message **m, const char* destination, const char *path, const char *interface, const char *member);
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
    TRY_DL(uv_dlsym(&libsystemd_h, "sd_bus_error_has_name", (void **) &sd_bus_error_has_name_f));
    TRY_DL(uv_dlsym(&libsystemd_h, "sd_bus_error_set_errno", (void **) &sd_bus_error_set_errno_f));
    TRY_DL(uv_dlsym(&libsystemd_h, "sd_bus_flush_close_unref", (void **) &sd_bus_flush_close_unref_f));
    TRY_DL(uv_dlsym(&libsystemd_h, "sd_bus_get_property", (void **) &sd_bus_get_property_f));
    TRY_DL(uv_dlsym(&libsystemd_h, "sd_bus_is_bus_client", (void **) &sd_bus_is_bus_client_f));
    TRY_DL(uv_dlsym(&libsystemd_h, "sd_bus_message_appendv", (void **) &sd_bus_message_appendv_f));
    TRY_DL(uv_dlsym(&libsystemd_h, "sd_bus_message_enter_container", (void **) &sd_bus_message_enter_container_f));
    TRY_DL(uv_dlsym(&libsystemd_h, "sd_bus_message_exit_container", (void **) &sd_bus_message_exit_container_f));
    TRY_DL(uv_dlsym(&libsystemd_h, "sd_bus_message_new_method_call", (void **) &sd_bus_message_new_method_call_f));
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

// Added to work around preprocessor time symbols missing
static void sd_bus_flush_close_unrefp_f(sd_bus **p) {
    if (*p) {
        sd_bus_flush_close_unref_f(*p);
    }
}

// Added to work around preprocessor time symbols missing
static void sd_bus_message_unrefp_f(sd_bus_message **p) {
    if (*p) {
        sd_bus_message_unref_f(*p);
    }
}

// Added to work around preprocessor time symbols missing
static void sd_bus_error_free_wrapper(sd_bus_error *e) {
    sd_bus_error_free_f(e);
}

// This replicates the functionality of
// sd_bus_call_methodv introduced in
// LIBSYSTEMD_246
static int sd_bus_call_method_va(
        sd_bus *bus,
        const char *destination,
        const char *path,
        const char *interface,
        const char *member,
        sd_bus_error *error,
        sd_bus_message **reply,
        const char *types,
        va_list ap) {

        _cleanup_(sd_bus_message_unrefp_f) sd_bus_message *m = NULL;
        int r;

        r = sd_bus_message_new_method_call_f(bus, &m, destination, path, interface, member);
        if (r < 0) {
            return sd_bus_error_set_errno_f(error, r);
        }

        if (types && !(types[0] == '\0')) {
                r = sd_bus_message_appendv_f(m, types, ap);
                if (r < 0) {
                    return sd_bus_error_set_errno_f(error, r);
                }
        }

        return sd_bus_call_f(bus, m, 0, error, reply);
}

static int sd_bus_run_command(sd_bus *bus, const char *destination, const char *path, const char *interface,  const char *command) {
    int r;
    _cleanup_(sd_bus_error_free_wrapper) sd_bus_error error = SD_BUS_ERROR_NULL;

    r = sd_bus_call_method_f(
            bus,
            destination,
            path,
            interface,
            command,
            &error,
            NULL,
            NULL);

    if (r < 0) {
        ZITI_LOG(ERROR, "Failed running command (%s): (%s, %s)", command, error.name, error.message);
        return r;
    }

    ZITI_LOG(DEBUG, "Success in command invocation: %s", command);
    return r;
}

static int sd_bus_is_acquired_name(sd_bus *bus, const char* bus_name) {
    int r;
    _cleanup_(sd_bus_message_unrefp_f) sd_bus_message *reply = NULL;
    _cleanup_(sd_bus_error_free_wrapper) sd_bus_error error = SD_BUS_ERROR_NULL;
    char **acquired = NULL;

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
        ZITI_LOG(ERROR, "Could not retrieve DBus bus names: (%s, %s)", error.name, error.message);
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
        if (strcmp(acquired[i], bus_name) == 0) {
            ZITI_LOG(DEBUG, "systemd-resolved DBus name found: %s", acquired[i]);
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

    if (found != 0) {
        ZITI_LOG(DEBUG, "systemd-resolved DBus name is NOT acquired");
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
        char *name;
        int is_routing_only;
    };

    struct s_domain domain;

    int routing_only_wildcard_set = 1;

    while ((r = sd_bus_message_read_f(reply, "(isb)", &domain.ifindex, &domain.name, &domain.is_routing_only)) > 0) {
        // Don't break out of loop when we find the route-only wildcard is set on a separate interface.
        // We must exhaust all container members before exiting the container.
        if ((domain.ifindex != ifindex) && (strcmp(domain.name, ".") == 0) && (domain.is_routing_only == 1)) {
            routing_only_wildcard_set = 0;
        }
    }

    if (routing_only_wildcard_set == 0) {
        ZITI_LOG(DEBUG, "systemd-resolved routing only domain wildcard found");
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

static bool set_systemd_resolved_link_setting(sd_bus *bus, const char *tun, const char *method, const char *method_type, ...) {
    _cleanup_(sd_bus_message_unrefp_f) sd_bus_message *reply = NULL;
    _cleanup_(sd_bus_error_free_wrapper) sd_bus_error error = SD_BUS_ERROR_NULL;

    int r;
    va_list ap;

    va_start(ap, method_type);

    r = sd_bus_call_method_va(
            bus,
            RESOLVED_DBUS_NAME,
            RESOLVED_DBUS_PATH,
            RESOLVED_DBUS_MANAGER_INTERFACE,
            method,
            &error,
            &reply,
            method_type,
            ap);

    va_end(ap);

    if (r < 0) {
        if (sd_bus_error_has_name_f(&error, SD_BUS_ERROR_UNKNOWN_METHOD)) {
            ZITI_LOG(WARN, "Attempted to call unknown method: %s for link: (%s)",
                    method, tun);
            return true;
        }

        ZITI_LOG(ERROR, "Failure calling method: %s for link: (%s): (%s, %s)",
                 method, tun, error.name, error.message);
        return false;
    }

    ZITI_LOG(DEBUG, "Success calling method: %s for link: (%s)", method, tun);

    return true;
}

// wait for systemd to recognize the tun device before configuring, lest the configuration get overwritten
static bool wait_for_tun(const char *name, sd_bus *bus, unsigned int timeout_ms) {
    const unsigned int delay_ms = 250;
    char systemd_path[128];
    unsigned int iterations = timeout_ms / delay_ms;
    bool active = false;
    snprintf(systemd_path, sizeof(systemd_path), "/org/freedesktop/systemd1/unit/sys_2dsubsystem_2dnet_2ddevices_2d%s_2edevice", name);

    ZITI_LOG(DEBUG, "waiting %d ms for systemd path '%s' to become active", timeout_ms, systemd_path);

    for (int count = 0; count < iterations && active == false; count++, uv_sleep(delay_ms)) {
        sd_bus_message *message = NULL;

        int r = sd_bus_get_property_f(
                bus,
                "org.freedesktop.systemd1",
                systemd_path,
                "org.freedesktop.systemd1.Unit",
                "ActiveState",
                NULL,
                &message,
                "s"
        );
        if (r < 0) {
            ZITI_LOG(VERBOSE, "failed to get ActiveState property: %s", strerror(-r));
            continue;
        }

        const char *state = NULL;
        r = sd_bus_message_read_f(message, "s", &state);
        if (r < 0) {
            ZITI_LOG(VERBOSE, "failed to read property: %s", strerror(-r));
        } else {
            if (state) {
                ZITI_LOG(DEBUG, "device state (c=%d): %s", count, state);
                if (strcmp(state, "active") == 0) {
                    active = true;
                }
            }
        }
        sd_bus_message_unref_f(message);
    }

    return false;
}

bool try_libsystemd_resolver(const char *tun_name) {
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
        wait_for_tun(tun_name, bus, 3000);
        r = sd_bus_is_acquired_name(bus, RESOLVED_DBUS_NAME);
        if (r != 0) {
            ZITI_LOG(WARN, "libsystemd resolver unsuccessful. Falling back to legacy resolvers");
            return false;
        }
        ZITI_LOG(INFO, "systemd-resolved selected as DNS resolver manager");
        return true;
    } else {
        ZITI_LOG(DEBUG, "Could not create system DBus client");
    }

    return false;
}

void dns_update_systemd_resolved(const char *tun, unsigned int ifindex, const char *addr) {
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

    r = detect_systemd_resolved_routing_domain_wildcard(bus, ifindex);

    switch(r) {
        case 0:
            ZITI_LOG(INFO, "Setting wildcard routing only domain on interface: %s", tun);
            RET_ON_FAIL(set_systemd_resolved_link_setting(bus, tun, "SetLinkDomains", "ia(sb)", ifindex, 1, ".", true));
            break;
        case 1:
            ZITI_LOG(DEBUG, "Setting empty domain on interface: %s", tun);
            RET_ON_FAIL(set_systemd_resolved_link_setting(bus, tun, "SetLinkDomains", "ia(sb)", ifindex, 0));
            break;
        default:
            ZITI_LOG(ERROR, "Error detecting systemd-resolved domain configuration: %s", strerror(-r));
            return;
    }

    sd_bus_run_command(bus, RESOLVED_DBUS_NAME, RESOLVED_DBUS_PATH, RESOLVED_DBUS_MANAGER_INTERFACE, "FlushCaches");
    sd_bus_run_command(bus, RESOLVED_DBUS_NAME, RESOLVED_DBUS_PATH, RESOLVED_DBUS_MANAGER_INTERFACE, "ResetServerFeatures");
}
#endif

void dns_update_resolvconf(const char *tun, unsigned int ifindex, const char *addr) {
    run_command("echo 'nameserver %s' | %s -a %s", addr, RESOLVCONF, tun);
}

static void cleanup_acl(acl_t *acl) {
    if (*acl != NULL) {
       if (acl_free(*acl) == -1) {
           ZITI_LOG(ERROR, "acl_free error: %s\n", strerror(errno));
       }
       *acl = NULL;
    }
}

#define ACL_EXIT(acl) do{                                          \
    ZITI_LOG(ERROR, "ACL operation failed: %s\n", strerror(errno)); \
    cleanup_acl(acl);                                              \
    return;                                                        \
} while(0)

#define CHECK_ACL(f) do{ \
    if ((f) == -1) {     \
        ACL_EXIT(&acl);  \
    }                    \
} while(0)


void install_user_acl_etc_resolv(uid_t uid) {

    _cleanup_(cleanup_acl) acl_t acl;
    acl_entry_t entry;
    acl_tag_t acl_tag_type;
    acl_permset_t permset;

    acl = acl_get_file(RESOLV_CONF_FILE, ACL_TYPE_ACCESS);
    if (acl == NULL) {
        ACL_EXIT(&acl);
    }

    bool acl_found = false;
    for (int entry_id = ACL_FIRST_ENTRY; ; entry_id = ACL_NEXT_ENTRY) {
        if (acl_get_entry(acl, entry_id, &entry) != 1) {
            break;
        }

        CHECK_ACL(acl_get_tag_type(entry, &acl_tag_type));

        if ( acl_tag_type == ACL_USER) {
            uid_t  *qualifier_uid = acl_get_qualifier(entry);
            if (qualifier_uid == NULL) {
                ACL_EXIT(&acl);
            }

            if (uid == *qualifier_uid) {
                acl_found = true;
                break;
            }
        }
    }

    if (acl_found) {
        CHECK_ACL(acl_get_permset(entry, &permset));

        int rd = acl_get_perm(permset, ACL_READ);
        CHECK_ACL(rd);
        int wr = acl_get_perm(permset, ACL_WRITE);
        CHECK_ACL(wr);

        if ( rd != 1 || wr != 1) {
            ZITI_LOG(TRACE, "[%s] ACL permissions are incorrect. Fixing...\n", RESOLV_CONF_FILE);
        } else {
            ZITI_LOG(DEBUG, "[%s] ACL permissions are already set.\n", RESOLV_CONF_FILE);
            return;
        }
    }

    if (!acl_found) {
        CHECK_ACL(acl_create_entry(&acl, &entry)); CHECK_ACL(acl_set_tag_type(entry, ACL_USER));
        CHECK_ACL(acl_set_qualifier(entry, &uid));
        CHECK_ACL(acl_get_permset(entry, &permset));
    }
    CHECK_ACL(acl_add_perm(permset, ACL_READ | ACL_WRITE));
    CHECK_ACL(acl_calc_mask(&acl));

    int r = acl_check(acl, NULL);

    switch (r) {
        case -1:
            ZITI_LOG(ERROR, "acl_check error: %s\n", strerror(errno));
            return;
        case 0:
            ZITI_LOG(TRACE, "ACL is valid. Proceeding with installation...\n");
            break;
        default:
            ZITI_LOG(ERROR, "ACL is invalid. Reason: %s\n", acl_error(r));
            return;
    }

    CHECK_ACL(acl_set_file(RESOLV_CONF_FILE, ACL_TYPE_ACCESS, acl));
    ZITI_LOG(INFO, "[%s] ACL permissions have been installed.\n", RESOLV_CONF_FILE);
    return;
}

static bool make_copy(const char *src, const char *dst) {

    uv_fs_t req = {0};

    ZITI_LOG(INFO, "attempting copy of: %s", src);

    int ret = uv_fs_copyfile(uv_default_loop(), &req, src, dst, UV_FS_COPYFILE_EXCL, NULL);

    if (req.result < 0) {
        if (req.result == UV_EEXIST) {
            ZITI_LOG(DEBUG, "%s has already been copied", req.path);
        } else {
            ZITI_LOG(WARN, "could not create copy[%s]: %s", req.new_path, uv_strerror(req.result));
            uv_fs_req_cleanup(&req);
            return false;
        }
    }

    ZITI_LOG(INFO, "copy successful: %s", req.new_path);

    uv_fs_req_cleanup(&req);

    return true;
}

static void cleanup_filep(FILE **file) {
    if (*file != NULL) {
        fclose(*file);
        *file = NULL;
    }
}

static void cleanup_bufferp(char **buffer) {
    if (*buffer != NULL) {
        free(*buffer);
        *buffer = NULL;
    }
}

void dns_update_etc_resolv(const char *tun, unsigned int ifindex, const char *addr) {
      bool copy_r = make_copy(RESOLV_CONF_FILE, RESOLV_CONF_FILE ".bkp");

      const char *match = "nameserver ";
      off_t replace_size = strlen(match) + strlen(addr) + sizeof(char);

      _cleanup_(cleanup_bufferp) char *replace = (char *)malloc((size_t)(replace_size + 1));
      if (replace == NULL){
          ZITI_LOG(ERROR, "error allocating replace buffer: %s", strerror(errno));
          exit(EXIT_FAILURE);
      }

      strcpy(replace, match);
      strcat(replace, addr);
      strcat(replace, "\n");

      _cleanup_(cleanup_filep) FILE *file = fopen(RESOLV_CONF_FILE, "r+");
      if (file == NULL) {
          ZITI_LOG(ERROR, "cannot open %s: %s", RESOLV_CONF_FILE, strerror(errno));
          ZITI_LOG(WARN, "run as 'root' or manually update your resolver configuration. Ziti DNS must be the first resolver: %s", addr);
          return;
      }

      _cleanup_(cleanup_bufferp) char *buffer = NULL;
      size_t buffer_size;
      ssize_t line_size;
      off_t match_start_offset = -1;

      while((line_size = getline(&buffer, &buffer_size, file)) != -1) {
          if(strstr(buffer, match) != NULL) {
              if(strstr(buffer, replace) != NULL) {
                  ZITI_LOG(DEBUG, "ziti nameserver is already in %s", RESOLV_CONF_FILE);
                  return;
              }
              match_start_offset = ftell(file) - line_size;
              break;
          }
      }

#define CLEANUP_ETC_RESOLV() do { \
    cleanup_bufferp(&replace); \
    cleanup_filep(&file); \
    exit(EXIT_FAILURE); \
} while(0)

      struct stat file_stat;
      if(stat(RESOLV_CONF_FILE, &file_stat) == -1){
          ZITI_LOG(ERROR, "cannot stat %s: %s", RESOLV_CONF_FILE, strerror(errno));
          CLEANUP_ETC_RESOLV();
      }

      // Slices everything after the matched line into a buffer,
      // inserts the ziti nameserver line, and flushes the buffer back to the file.
      if (match_start_offset >= 0) {

          off_t remaining_size = file_stat.st_size - match_start_offset;

          _cleanup_(cleanup_bufferp) char *remaining_content = (char *)malloc(remaining_size + 1);
          if (remaining_content == NULL) {
              ZITI_LOG(ERROR, "error allocating %s remaining content buffer: %s", RESOLV_CONF_FILE, strerror(errno));
              CLEANUP_ETC_RESOLV();
          }

          fseek(file, match_start_offset, SEEK_SET);
          if (fread(remaining_content, sizeof(char), (size_t)remaining_size, file) != remaining_size) {
              if (ferror(file) || feof(file)) {
                  ZITI_LOG(ERROR, "Error during file stream operation or EOF received.");
              }
              cleanup_bufferp(&remaining_content);
              CLEANUP_ETC_RESOLV();
          }
          remaining_content[remaining_size] = '\0';

          _cleanup_(cleanup_bufferp) char *rptr = realloc(replace, (size_t)(replace_size + remaining_size + 1));
          if (rptr == NULL) {
              ZITI_LOG(ERROR, "cannot realloc");
              cleanup_bufferp(&remaining_content);
              CLEANUP_ETC_RESOLV();
          }

          // prevent double free() when cleanup_bufferp() is called
          replace = NULL;

          strcat(rptr, remaining_content);

          fseek(file, match_start_offset, SEEK_SET);

          if (fputs(rptr, file) == EOF) {
              ZITI_LOG(ERROR, "EOF received while writing file. Attempting to restore file to original content...");
              fseek(file, match_start_offset, SEEK_SET);
              if (fputs(remaining_content, file) == EOF) {
                  ZITI_LOG(ERROR, "EOF received while restoring file."); 
                  if (copy_r) {
                      ZITI_LOG(ERROR, "Backup location: %s", RESOLV_CONF_FILE ".bkp");
                  }
                  cleanup_bufferp(&remaining_content);
                  cleanup_bufferp(&rptr);
                  CLEANUP_ETC_RESOLV();
              }
          }

      } else {
          // If no nameserver directives to prepend, just append to the file.
          if (fputs(replace, file) == EOF) {
              ZITI_LOG(ERROR, "EOF received while appending to: %s", RESOLV_CONF_FILE);
              CLEANUP_ETC_RESOLV();
          }
      }

      ZITI_LOG(DEBUG, "Added ziti DNS resolver to %s", RESOLV_CONF_FILE);

      return;
}

bool is_systemd_resolved_primary_resolver(void){
    if (is_symlink(RESOLV_CONF_FILE)){

        const char *valid_links[] = {
            "/run/systemd/resolve/stub-resolv.conf",
            "/run/systemd/resolve/resolv.conf",
            "/usr/lib/systemd/resolv.conf",
            "/lib/systemd/resolv.conf"
        };

        char buf[PATH_MAX];
        char *actualpath = realpath(RESOLV_CONF_FILE, buf);

        if (actualpath != NULL) {
            for (int idx = 0; idx < (sizeof(valid_links) / sizeof(valid_links[0])); idx++) {
                if (strcmp(actualpath, valid_links[idx]) == 0) {
                    ZITI_LOG(INFO, "Detected systemd-resolved is primary system resolver");
                    return true;
                }
            }
        }
    }

    return false;
}

bool is_resolvconf_systemd_resolved(void) {
    if (is_symlink(RESOLVCONF)) {
        char buf[PATH_MAX];
        char *actualpath = realpath(RESOLVCONF, buf);

        if (actualpath != NULL) {
            char *file_base = basename(actualpath);
            if (strcmp(file_base, basename(RESOLVECTL)) == 0
                || strcmp(file_base, basename(SYSTEMD_RESOLVE)) == 0) {
                ZITI_LOG(DEBUG, "Detected %s is a symlink to systemd-resolved", actualpath);
                return true;
            }
        }
    }
    return false;
}
