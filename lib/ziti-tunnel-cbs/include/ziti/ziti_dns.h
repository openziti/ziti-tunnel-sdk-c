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

#ifndef ZITI_TUNNEL_SDK_C_ZITI_DNS_H
#define ZITI_TUNNEL_SDK_C_ZITI_DNS_H

#include <ziti/ziti_tunnel.h>

#include "ziti_tunnel_cbs.h"

#define DNS_NO_ERROR 0
#define DNS_FORMERR  1
#define DNS_SERVFAIL 2
#define DNS_NXDOMAIN 3
#define DNS_NOT_IMPL 4
#define DNS_REFUSE   5
#define DNS_NOTZONE  9

#ifdef __cplusplus
extern "C" {
#endif

int ziti_dns_setup(tunneler_context tnlr, const char *dns_addr, const char *dns_cidr);

int ziti_dns_set_upstream(uv_loop_t *l, tunnel_upstream_dns_array upstreams);

const ip_addr_t *ziti_dns_register_hostname(const ziti_address *addr, void *intercept);

const char *ziti_dns_reverse_lookup_domain(const ip_addr_t *addr);

const char *ziti_dns_reverse_lookup(const char *ip_addr);

void ziti_dns_deregister_intercept(void *intercept);

/**
 * Returns the sorted, NULL-terminated list of hostnames and wildcard domains (without the leading "*.")
 * that are currently intercepted, or NULL when out of memory. The caller owns the list and each element.
 */
char **ziti_dns_get_domains(void);

/**
 * Fit a list of routing domains (as from ziti_dns_get_domains()) into `limit` entries, for resolvers that limit
 * the number of routing domains (systemd-resolved: 1024 per link). Routing domains match a name and all names
 * below it, so names are merged into common parent domains: deepest parents first, largest groups first, never
 * into a parent with fewer than two labels, and never into a parent that equals or is below one of the
 * `reserved` domains (NULL-terminated, may be NULL), e.g. domains that other links route.
 * The list is changed in place: removed names are freed, merged parents are allocated, the result is sorted
 * and NULL-terminated, and the caller still owns the list and each element.
 * Returns the number of entries, which is above `limit` if the names could not be merged enough.
 * Lists within the limit are not changed.
 */
size_t ziti_dns_compact_domains(char **domains, size_t limit, const char *const *reserved);

/** true if queries that do not match an intercepted name can be forwarded to an upstream resolver */
bool ziti_dns_has_upstream(void);

/**
 * Set resolvers for queries that do not match an intercepted name, used only while no upstream is configured
 * with ziti_dns_set_upstream(). Unlike a configured upstream, a fallback does not make the tunneler a default
 * DNS route; it only answers names that the OS routes to the tunneler because they share a suffix with an
 * intercepted name (e.g. "www.corp.example" when "corp.example" is intercepted).
 * When the fallback is used more than max_age_ms after it was set, the netif driver is asked to refresh it
 * (dns_refresh_fallback). 0 never refreshes.
 */
int ziti_dns_set_fallback_upstream(uv_loop_t *l, const struct sockaddr_storage *addrs, size_t count,
                                   uint64_t max_age_ms);

#ifdef __cplusplus
};
#endif

#endif //ZITI_TUNNEL_SDK_C_ZITI_DNS_H
