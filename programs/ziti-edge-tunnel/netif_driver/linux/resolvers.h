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
#include <sys/types.h>

#ifndef BUSCTL
#define BUSCTL "/usr/bin/busctl"
#endif

#ifndef RESOLV_CONF_FILE
#define RESOLV_CONF_FILE "/etc/resolv.conf"
#endif
#ifndef RESOLVCONF
#define RESOLVCONF "/usr/sbin/resolvconf"
#endif
#ifndef RESOLVECTL
#define RESOLVECTL "/usr/bin/resolvectl"
#endif
#ifndef SYSTEMD_RESOLVE
#define SYSTEMD_RESOLVE "/usr/bin/systemd-resolve"
#endif

#ifndef RESOLVED_DBUS_NAME
#define RESOLVED_DBUS_NAME "org.freedesktop.resolve1"
#endif

#ifndef RESOLVED_DBUS_PATH
#define RESOLVED_DBUS_PATH "/org/freedesktop/resolve1"
#endif

#ifndef RESOLVED_DBUS_MANAGER_INTERFACE
#define RESOLVED_DBUS_MANAGER_INTERFACE "org.freedesktop.resolve1.Manager"
#endif

#ifndef EXCLUDE_LIBSYSTEMD_RESOLVER
bool try_libsystemd_resolver(void);
#endif
bool is_systemd_resolved_primary_resolver(void);
bool is_resolvconf_systemd_resolved(void);
void dns_update_systemd_resolved(const char* tun, unsigned int ifindex, const char* addr);
void dns_update_resolvconf(const char* tun, unsigned int ifindex, const char* addr);
void dns_update_etc_resolv(const char* tun, unsigned int ifindex, const char* addr);

#ifdef HAVE_LIBACL_PKG
void install_user_acl_etc_resolv(uid_t uid);
#endif
