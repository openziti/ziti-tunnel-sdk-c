/*
Copyright 2020 Netfoundry, Inc.

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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "ziti/sys/queue.h"

#define MAX_DNS_NAME 256
#define MAX_IP_LENGTH 16

struct dns_entry {
    char hostname[MAX_DNS_NAME];
    char ip[MAX_IP_LENGTH];
    LIST_ENTRY(dns_entry) _next;
};

typedef struct cache_s {
    uint32_t base;
    uint32_t counter;
    uint32_t counter_bits;
    LIST_HEAD(dns, dns_entry) entries;
} cache;

static cache ip_cache = {
        .base = 0x64400000, // 100.64.0.0
        .counter = 0x00000201, // 0.0.1.1 -- starting
        .counter_bits = 0x3fffff, // 10-bit netmask
        .entries = {0},
};

void ziti_tunneler_init_dns(uint32_t mask, int bits) {
    if (bits > 32 || bits < 8) bits = 16;
    ip_cache.base = mask;
    ip_cache.counter_bits = ~( (uint32_t)-1 << (32 - (uint32_t)bits));
}

const char* assign_ip(const char *hostname) {
    char canonical[MAX_DNS_NAME];
    char *p = canonical;
    const char *hp = hostname;
    while (*hp) {
        *p++ = (char)tolower(*hp++);
    }
    *p = 0;

    struct dns_entry *e;
    LIST_FOREACH(e, &ip_cache.entries, _next) {
        if (strcmp(e->hostname, canonical) == 0) break;
    }

    if (e != NULL) {
        return e->ip;
    }

    e = calloc(1, sizeof(struct dns_entry));
    uint32_t addr = ip_cache.base | (ip_cache.counter++ & ip_cache.counter_bits);
    if (ip_cache.counter > ip_cache.counter_bits) {
        fprintf(stderr, "WARN: DNS assignment space is exhausted");
    }
    snprintf(e->ip, MAX_IP_LENGTH, "%d.%d.%d.%d", addr>>24U, (addr>>16U) & 0xFFU, (addr>>8U)&0xFFU, addr&0xFFU);
    snprintf(e->hostname, sizeof(e->hostname), "%s", canonical);

    LIST_INSERT_HEAD(&ip_cache.entries, e, _next);
    return e->ip;
}
