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

#include <string.h>
#include <stdio.h>

#include "ziti_tunnel_priv.h"
#include "ziti/ziti_model.h"

bool protocol_match(const char *protocol, const protocol_list_t *protocols) {
    protocol_t *p;
    STAILQ_FOREACH(p, protocols, entries) {
        if (strcmp(p->protocol, protocol) == 0) {
            return true;
        }
    }
    return false;
}

void ziti_address_from_in_addr(ziti_address *za, const struct in_addr *a) {
    memset(za, 0, sizeof(ziti_address));
    za->type = ziti_address_cidr;
    za->addr.cidr.af = AF_INET;
    za->addr.cidr.bits = 32;
    struct in_addr *zin = (struct in_addr *)&za->addr.cidr.ip;
    zin->s_addr = a->s_addr;
}

void ziti_address_from_in6_addr(ziti_address *za, const struct in6_addr *a) {
    memset(za, 0, sizeof(ziti_address));
    za->type = ziti_address_cidr;
    za->addr.cidr.af = AF_INET6;
    za->addr.cidr.bits = 128;
    memcpy(&za->addr.cidr.ip, &a, sizeof(struct in6_addr));
}

void ziti_address_from_sockaddr_in(ziti_address *za, const struct sockaddr_in *sin) {
    ziti_address_from_in_addr(za, &sin->sin_addr);
}

void ziti_address_from_sockaddr_in6(ziti_address *za, const struct sockaddr_in6 *sin6) {
    ziti_address_from_in6_addr(za, &sin6->sin6_addr);
}

bool ziti_address_from_sockaddr(ziti_address *za, const struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        ziti_address_from_sockaddr_in(za, (struct sockaddr_in *)sa);
    } else if (sa->sa_family == AF_INET6) {
        ziti_address_from_sockaddr_in6(za, (struct sockaddr_in6 *)sa);
    } else {
        TNL_LOG(ERR, "unknown address family %d", sa->sa_family);
        return false;
    }

    return true;
}

void ziti_address_from_ip4_addr(ziti_address *za, const ip4_addr_t *ip4) {
    struct in_addr in = { 0 };
    in.s_addr = ip4->addr;
    ziti_address_from_in_addr(za, &in);
}

void ziti_address_from_ip6_addr(ziti_address *za, const ip6_addr_t *ip6) {
    ziti_address_from_in6_addr(za, (struct in6_addr *)ip6);
}

bool ziti_address_from_ip_addr(ziti_address *zaddr, const ip_addr_t *ip) {
    if (ip->type == IPADDR_TYPE_V4) {
        ziti_address_from_ip4_addr(zaddr, &ip->u_addr.ip4);
    } else if (ip->type == IPADDR_TYPE_V6) {
        ziti_address_from_ip6_addr(zaddr, &ip->u_addr.ip6);
    } else {
        TNL_LOG(ERR, "unknown address type %d", ip->type);
        return false;
    }

    return true;
}

bool address_match(const ziti_address *addr, const address_list_t *addresses) {
    address_t *a;
    STAILQ_FOREACH(a, addresses, entries) {
        if (ziti_address_match(addr, &a->za)) {
            return true;
        }
    }
    return false;
}

bool port_match(int port, const port_range_list_t *port_ranges) {
    port_range_t *pr;
    STAILQ_FOREACH(pr, port_ranges, entries) {
        if (port >= pr->low && port <= pr->high) {
            return true;
        }
    }
    return false;
}

/** return the intercept context for a packet based on its destination ip:port */
intercept_ctx_t *lookup_intercept_by_address(tunneler_context tnlr_ctx, const char *protocol, ip_addr_t *dst_addr, uint16_t dst_port) {
    if (tnlr_ctx == NULL) {
        TNL_LOG(DEBUG, "null tnlr_ctx");
        return NULL;
    }

    ziti_address za;
    ziti_address_from_ip_addr(&za, dst_addr);
    intercept_ctx_t *intercept;
    LIST_FOREACH(intercept, &tnlr_ctx->intercepts, entries) {
        if (!protocol_match(protocol, &intercept->protocols)) continue;
        if (!port_match(dst_port, &intercept->port_ranges)) continue;

        if (intercept->match_addr && intercept->match_addr(dst_addr, intercept->app_intercept_ctx))
            return intercept;

        if (address_match(&za, &intercept->addresses))
            return intercept;
    }

    return NULL;
}

void free_intercept(intercept_ctx_t *intercept) {
    while(!STAILQ_EMPTY(&intercept->addresses)) {
        address_t *a = STAILQ_FIRST(&intercept->addresses);
        STAILQ_REMOVE_HEAD(&intercept->addresses, entries);
        free_ziti_address(&a->za);
        free(a);
    }
    while(!STAILQ_EMPTY(&intercept->protocols)) {
        protocol_t *p = STAILQ_FIRST(&intercept->protocols);
        STAILQ_REMOVE_HEAD(&intercept->protocols, entries);
        free(p->protocol);
        free(p);
    }
    while(!STAILQ_EMPTY(&intercept->port_ranges)) {
        port_range_t *pr = STAILQ_FIRST(&intercept->port_ranges);
        STAILQ_REMOVE_HEAD(&intercept->port_ranges, entries);
        free(pr);
    }

    free(intercept->service_name);
    free(intercept);
}