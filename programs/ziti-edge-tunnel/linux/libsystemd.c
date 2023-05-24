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

#include <stdbool.h>
#include <stdlib.h>

#include <uv.h>

#include "linux/libsystemd.h"
#include <ziti/ziti_log.h>

#define TRY_DL(dl_func) do{if ((dl_func) != 0) goto dl_error;} while(0)


bool libsystemd_dl_success = true;
static uv_lib_t libsystemd_h;

int (*sd_booted_f)(void);
int (*sd_bus_call_f)(sd_bus *bus, sd_bus_message *m, uint64_t usec, sd_bus_error *ret_error, sd_bus_message **reply);
int (*sd_bus_call_method_f)(sd_bus *bus, const char *destination, const char *path, const char *interface, const char *member, sd_bus_error *ret_error, sd_bus_message **reply, const char *types, ...);
void (*sd_bus_error_free_f)(sd_bus_error *e);
int (*sd_bus_error_has_name_f)(const sd_bus_error *e, const char *name);
int (*sd_bus_error_set_errno_f)(sd_bus_error *e, int error);
sd_bus *(*sd_bus_flush_close_unref_f)(sd_bus *bus);
int (*sd_bus_get_property_f)(sd_bus *bus, const char *destination, const char *path, const char *interface, const char *member, sd_bus_error *ret_error, sd_bus_message **reply, const char *type);
int (*sd_bus_is_bus_client_f)(sd_bus *bus);
int (*sd_bus_message_appendv_f)(sd_bus_message *m, const char *types, va_list ap);
int (*sd_bus_message_enter_container_f)(sd_bus_message *m, char type, const char *contents);
int (*sd_bus_message_exit_container_f)(sd_bus_message *m);
int (*sd_bus_message_new_method_call_f)(sd_bus *bus, sd_bus_message **m, const char* destination, const char *path, const char *interface, const char *member);
int (*sd_bus_message_read_f)(sd_bus_message *m, const char *types, ...);
int (*sd_bus_message_read_strv_f)(sd_bus_message *m, char ***l);
sd_bus_message *(*sd_bus_message_unref_f)(sd_bus_message *m);
int (*sd_bus_open_system_f)(sd_bus **bus);
int (*sd_listen_fds_f)(int unset_environment);
int (*sd_is_socket_unix_f)(int fd, int type, int listening, const char *path, size_t length);

void init_libsystemd(void) {
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
    TRY_DL(uv_dlsym(&libsystemd_h, "sd_listen_fds", (void **) &sd_listen_fds_f));
    TRY_DL(uv_dlsym(&libsystemd_h, "sd_is_socket_unix", (void **) &sd_is_socket_unix_f));

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
void sd_bus_flush_close_unrefp_f(sd_bus **p) {
    if (*p) {
        sd_bus_flush_close_unref_f(*p);
    }
}

// Added to work around preprocessor time symbols missing
void sd_bus_message_unrefp_f(sd_bus_message **p) {
    if (*p) {
        sd_bus_message_unref_f(*p);
    }
}

// Added to work around preprocessor time symbols missing
void sd_bus_error_free_wrapper(sd_bus_error *e) {
    sd_bus_error_free_f(e);
}

// This replicates the functionality of
// sd_bus_call_methodv introduced in
// LIBSYSTEMD_246
int sd_bus_call_method_va(
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

int sd_bus_run_command(sd_bus *bus, const char *destination, const char* path, const char* interface,  const char* command) {
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

int sd_bus_is_acquired_name(sd_bus *bus, const char* bus_name) {
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
