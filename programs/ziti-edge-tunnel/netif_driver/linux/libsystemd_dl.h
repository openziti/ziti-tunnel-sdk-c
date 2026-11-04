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

// libsystemd is loaded at runtime (resolvers.c), so the tunneler also runs on systems without it.
// This header shares the loaded functions with the other systemd-resolved code.

#ifndef ZITI_TUNNELER_SDK_LIBSYSTEMD_DL_H
#define ZITI_TUNNELER_SDK_LIBSYSTEMD_DL_H

#include <stdbool.h>

#define _cleanup_(f) __attribute__((cleanup(f)))

#ifndef EXCLUDE_LIBSYSTEMD_RESOLVER
#include <stdarg.h>
#include <stdint.h>
#include <systemd/sd-bus.h>

#define RET_ON_FAIL(bool_func) do{if (!(bool_func)) return;} while(0)

// loads libsystemd once; false if it is not available
bool libsystemd_load(void);

extern int (*sd_booted_f)(void);
extern int (*sd_bus_call_f)(sd_bus *bus, sd_bus_message *m, uint64_t usec, sd_bus_error *ret_error, sd_bus_message **reply);
extern int (*sd_bus_call_method_f)(sd_bus *bus, const char *destination, const char *path, const char *interface, const char *member, sd_bus_error *ret_error, sd_bus_message **reply, const char *types, ...);
extern void (*sd_bus_error_free_f)(sd_bus_error *e);
extern int (*sd_bus_error_has_name_f)(const sd_bus_error *e, const char *name);
extern int (*sd_bus_error_set_errno_f)(sd_bus_error *e, int error);
extern sd_bus *(*sd_bus_flush_close_unref_f)(sd_bus *bus);
extern int (*sd_bus_get_property_f)(sd_bus *bus, const char *destination, const char *path, const char *interface, const char *member, sd_bus_error *ret_error, sd_bus_message **reply, const char *type);
extern int (*sd_bus_is_bus_client_f)(sd_bus *bus);
extern int (*sd_bus_message_append_f)(sd_bus_message *m, const char *types, ...);
extern int (*sd_bus_message_appendv_f)(sd_bus_message *m, const char *types, va_list ap);
extern int (*sd_bus_message_open_container_f)(sd_bus_message *m, char type, const char *contents);
extern int (*sd_bus_message_close_container_f)(sd_bus_message *m);
extern int (*sd_bus_message_enter_container_f)(sd_bus_message *m, char type, const char *contents);
extern int (*sd_bus_message_exit_container_f)(sd_bus_message *m);
extern int (*sd_bus_message_new_method_call_f)(sd_bus *bus, sd_bus_message **m, const char* destination, const char *path, const char *interface, const char *member);
extern int (*sd_bus_message_read_f)(sd_bus_message *m, const char *types, ...);
extern int (*sd_bus_message_read_array_f)(sd_bus_message *m, char type, const void **ptr, size_t *size);
extern int (*sd_bus_message_read_strv_f)(sd_bus_message *m, char ***l);
extern sd_bus_message *(*sd_bus_message_unref_f)(sd_bus_message *m);
extern int (*sd_bus_open_system_f)(sd_bus **bus);

int sd_bus_run_command(sd_bus *bus, const char *destination, const char *path, const char *interface, const char *command);
bool set_systemd_resolved_link_setting(sd_bus *bus, const char *tun, const char *method, const char *method_type, ...);

// cleanup helpers for the loaded functions (the libsystemd macros expect the real symbols)
static inline void sd_bus_flush_close_unrefp_f(sd_bus **p) {
    if (*p) {
        sd_bus_flush_close_unref_f(*p);
    }
}

static inline void sd_bus_message_unrefp_f(sd_bus_message **p) {
    if (*p) {
        sd_bus_message_unref_f(*p);
    }
}

static inline void sd_bus_error_free_wrapper(sd_bus_error *e) {
    sd_bus_error_free_f(e);
}
#endif // EXCLUDE_LIBSYSTEMD_RESOLVER

#endif // ZITI_TUNNELER_SDK_LIBSYSTEMD_DL_H
