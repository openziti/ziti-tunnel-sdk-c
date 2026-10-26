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

// split DNS with systemd-resolved: the intercepted names become routing domains of the tunnel's link

#ifndef ZITI_TUNNELER_SDK_RESOLVED_DNS_H
#define ZITI_TUNNELER_SDK_RESOLVED_DNS_H

#ifndef EXCLUDE_LIBSYSTEMD_RESOLVER
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

/**
 * Configure the tunnel's link in systemd-resolved: its DNS server, the intercepted names as routing-only domains,
 * and whether the link is a default route (only when the ziti resolver has an upstream for other names).
 * `domains` may be modified (merged into parent domains when there are more than systemd-resolved accepts).
 */
void dns_update_systemd_resolved(const char *tun, unsigned int ifindex, const char *addr, char **domains, bool default_route);

/** Return 1 if the tunnel's ~. routing domain differs from other links, 0 if it matches, or a negative error. */
int systemd_resolved_wildcard_mismatch(int32_t own_ifindex);

/**
 * The DNS servers systemd-resolved uses for names that no routing domain matches, other than the ones on the
 * given link and the given IP (network byte order). Names below an intercepted name are forwarded to them.
 * Returns the number of servers stored in addrs, or a negative error.
 */
int systemd_resolved_get_dns_servers(int32_t exclude_ifindex, uint32_t exclude_ip, struct sockaddr_storage *addrs, size_t max);
#endif

#endif // ZITI_TUNNELER_SDK_RESOLVED_DNS_H
