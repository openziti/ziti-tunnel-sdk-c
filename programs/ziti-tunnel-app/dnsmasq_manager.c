/*
Copyright 2019 Netfoundry, Inc.

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

#include <ziti/ziti_tunneler.h>
#include <ziti/model_support.h>
#include <string.h>
#include <unistd.h>

static const char* map_to_ip(dns_manager *dns, const char *hostname);

typedef struct cache_s {
    uint32_t base;
    uint32_t counter;
    model_map cache;
} cache;

static cache ip_cache = {
        .base = 0xA9FE0000, // 169.254.0.0
        .counter = 0x00000201, // 0.0.2.1 -- starting
};


static dns_manager dnsmasq_manager = {
        .map_to_ip = map_to_ip,
        .data = &ip_cache
};

#define DNS_HOSTS_DIR "/tmp/hosts/"
static void apply_address(const char *hostname, const char *ip) {
    char fname[PATH_MAX];
    sprintf(fname, DNS_HOSTS_DIR "%s", hostname);

    char entry[512];
    int c = snprintf(entry, sizeof(entry), "%s\t%s", ip, hostname);
    FILE *rec = fopen(fname, "wb");
    fwrite(entry, 1, c, rec);
    fflush(rec);
    fclose(rec);

    system("killall -HUP dnsmasq");
}

static const char* map_to_ip(dns_manager *dns, const char *hostname) {
    cache *c = dns->data;

    char *ip;
    if ((ip = model_map_get(&c->cache, hostname)) != NULL) {
        return ip;
    }

    uint32_t addr = c->base | c->counter++;
    ip = calloc(1, 16);
    sprintf(ip, "%d.%d.%d.%d", addr>>24U, (addr>>16U) & 0xFFU, (addr>>8U)&0xFFU, addr&0xFFU);

    model_map_set(&c->cache, hostname, ip);

    apply_address(hostname, ip);
    return ip;
}

dns_manager *get_dnsmasq_manager() {
    return &dnsmasq_manager;
}

