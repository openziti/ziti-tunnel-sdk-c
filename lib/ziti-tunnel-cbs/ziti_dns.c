/*
 Copyright 2019-2021 NetFoundry Inc.

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

#include <ziti/ziti_tunnel.h>
#include <ziti/ziti_log.h>
#include <ziti/ziti_dns.h>
#include <ziti/model_support.h>
#include "ziti_instance.h"

#define MAX_DNS_NAME 256
#define MAX_IP_LENGTH 16

typedef struct ziti_dns_client_s {
    io_ctx_t *io_ctx;
    LIST_HEAD(reqs, dns_req) active_reqs;
} ziti_dns_client_t;

struct dns_req {
    char host[255];
    dns_fallback_cb fallback;
    void *fb_ctx;

    struct in_addr addr;
    int code;

    uint8_t resp[512];
    uint8_t *rp;

    ziti_dns_client_t *clt;
    LIST_ENTRY(dns_req) _next;
};

static void* on_dns_client(const void *app_intercept_ctx, io_ctx_t *io);
static int on_dns_close(void *dns_io_ctx);
static ssize_t on_dns_req(void *ziti_io_ctx, void *write_ctx, const uint8_t *q_packet, size_t len);


// hostname or domain
typedef struct dns_entry_s {
    char name[MAX_DNS_NAME];
    char ip[MAX_IP_LENGTH];
    ip_addr_t addr;

    ziti_intercept_t  *intercept;
} dns_entry_t;

struct ziti_dns_s {

    struct {
        uint32_t base;
        uint32_t counter;
        uint32_t counter_mask;
    } ip_pool;

    // map[hostname -> dns_entry_t]
    model_map hostnames;

    // map[ip -> dns_entry_t]
    model_map ip_addresses;

    // map[domain -> dns_entry_t]
    model_map domains;

    dns_fallback_cb fallback_cb;
    void * fallback_ctx;
    uv_loop_t *loop;
    tunneler_context tnlr;
} ziti_dns;


static uint32_t next_ipv4() {
   return  htonl(ziti_dns.ip_pool.base | (ziti_dns.ip_pool.counter++ & ziti_dns.ip_pool.counter_mask));
}

static int seed_dns(const char *dns_cidr) {
    uint32_t ip[4];
    uint32_t bits;
    int rc = sscanf(dns_cidr, "%d.%d.%d.%d/%d", &ip[0], &ip[1], &ip[2], &ip[3], &bits);
    if (rc != 5 || ip[0] > 255 || ip[1] > 255 || ip[2] > 255 || ip[3] > 255 || bits > 32) {
        ZITI_LOG(ERROR, "Invalid IP range specification: n.n.n.n/m format is expected");
        return -1;
    }
    uint32_t mask = 0;
    for (int i = 0; i < 4; i++) {
        mask <<= 8U;
        mask |= (ip[i] & 0xFFU);
    }

    ziti_dns.ip_pool.base = mask;
    ziti_dns.ip_pool.counter = 10;
    ziti_dns.ip_pool.counter_mask = ~( (uint32_t)-1 << (32 - (uint32_t)bits));
}

int ziti_dns_setup(tunneler_context tnlr, const char *dns_addr, const char *dns_cidr) {
    ziti_dns.tnlr = tnlr;
    seed_dns(dns_cidr);

    intercept_ctx_t *dns_intercept = intercept_ctx_new(tnlr, "ziti:dns-resolver", &ziti_dns);
    intercept_ctx_add_address(dns_intercept, dns_addr);
    intercept_ctx_add_port_range(dns_intercept, 53, 53);
    intercept_ctx_add_protocol(dns_intercept, "udp");

    intercept_ctx_override_cbs(dns_intercept, on_dns_client, on_dns_req, on_dns_close, on_dns_close);

    ziti_tunneler_intercept(tnlr, dns_intercept);
    return 0;
}

void ziti_dns_set_fallback(uv_loop_t *loop, dns_fallback_cb fb, void *ctx) {
    ziti_dns.loop = loop;
    ziti_dns.fallback_cb = fb;
    ziti_dns.fallback_ctx = ctx;
}

void* on_dns_client(const void *app_intercept_ctx, io_ctx_t *io) {
    ZITI_LOG(INFO, "new DNS client");
    ziti_dns_client_t *clt = calloc(1, sizeof(ziti_dns_client_t));
    io->ziti_io = clt;
    clt->io_ctx = io;
    ziti_tunneler_set_idle_timeout(io, 5000); // 5 seconds
    ziti_tunneler_dial_completed(io, true);
    return clt;
}

int on_dns_close(void *dns_io_ctx) {
    ZITI_LOG(TRACE, "DNS client close");
    ziti_dns_client_t *clt = dns_io_ctx;
    while(!LIST_EMPTY(&clt->active_reqs)) {
        struct dns_req *req = LIST_FIRST(&clt->active_reqs);
        LIST_REMOVE(req, _next);
        req->clt = NULL;
    }
    ziti_tunneler_close(clt->io_ctx->tnlr_io);
    free(clt->io_ctx);
    free(dns_io_ctx);
}

static bool check_name(const char *name, char clean_name[MAX_DNS_NAME], bool *is_domain) {
    const char *hp = name;
    char *p = clean_name;

    if (*hp == '*' && *(hp + 1) == '.') {
        *is_domain = true;
        *p++ = '.';
        hp += 2;
    } else {
        *is_domain = false;
    }

    bool need_alphanum = true;
    while (*hp != '\0') {
        if (!isalnum(*hp) && *hp != '-' && *hp != '.') { return false; }
        if (!isalnum(*hp) && need_alphanum) return false;

        need_alphanum = *hp == '.';

        *p++ = (char) tolower(*hp++);
    }
    *p = '\0';
    return true;
}

static dns_entry_t* new_ipv4_entry(const char *host) {
    dns_entry_t *entry = calloc(1, sizeof(dns_entry_t));
    strncpy(entry->name, host, sizeof(entry->name));
    entry->addr.type = IPADDR_TYPE_V4;
    entry->addr.u_addr.ip4.addr = next_ipv4();
    ip4addr_ntoa_r(&entry->addr.u_addr.ip4, entry->ip, sizeof(entry->ip));

    model_map_set(&ziti_dns.hostnames, host, entry);
    model_map_set(&ziti_dns.ip_addresses, entry->ip, entry);
    ZITI_LOG(INFO, "registered DNS entry %s -> %s", host, entry->ip);

    return entry;
}

const char *ziti_dns_reverse_lookup(const char *ip_addr) {
    dns_entry_t *entry = model_map_get(&ziti_dns.ip_addresses, ip_addr);

    return entry ? entry->name : NULL;
}

dns_entry_t *ziti_dns_lookup(const char *hostname) {
    char clean[MAX_DNS_NAME];
    bool is_wildcard;
    if (!check_name(hostname, clean, &is_wildcard) || is_wildcard) {
        ZITI_LOG(ERROR, "invalid host lookup[%s]", hostname);
        return NULL;
    }

    dns_entry_t *entry = model_map_get(&ziti_dns.hostnames, clean);
    if (entry) {
        return entry;
    }

    // try domains
    char *dot = strchr(clean, '.');
    while (dot != NULL) {
        entry = model_map_get(&ziti_dns.domains, dot);
        if (entry) {
            ZITI_LOG(DEBUG, "matching domain[%s] found for %s", entry->name, hostname);
            dns_entry_t *host_entry = new_ipv4_entry(clean);
            host_entry->intercept = entry->intercept;
            intercept_ctx_t *intercept = ziti_tunnel_find_intercept(ziti_dns.tnlr, entry->intercept);
            if (intercept) {
                intercept_ctx_add_address(intercept, host_entry->ip);
            } else {
                ZITI_LOG(ERROR, "could not find matching tunnel intercept for intercepted domain[%s]", entry->name);
            }
            return host_entry;
        }
        dot = strchr(dot + 1, '.');
    }
    return NULL;
}

void ziti_dns_deregister_intercept(void *intercept) {
    model_map_iter it = model_map_iterator(&ziti_dns.domains);
    while (it != NULL) {
        dns_entry_t *e = model_map_it_value(it);
        if (e->intercept == intercept) {
            it = model_map_it_remove(it);
            ZITI_LOG(INFO, "removed wildcard domain[*%s]", e->name);
            free(e);
        } else {
            it = model_map_it_next(it);
        }
    }

    it = model_map_iterator(&ziti_dns.hostnames);
    while (it != NULL) {
        dns_entry_t *e = model_map_it_value(it);
        if (e->intercept == intercept) {
            it = model_map_it_remove(it);
            model_map_remove(&ziti_dns.ip_addresses, e->ip);
            ZITI_LOG(INFO, "removed DNS mapping %s -> %s", e->name, e->ip);
            free(e);
        } else {
            it = model_map_it_next(it);
        }
    }
}

const char *ziti_dns_register_hostname(const char *hostname, void *intercept) {
    // CIDR block
    if (strchr(hostname, '/')) {
        return hostname;
    }
    // IP address
    ip_addr_t addr;
    if (ipaddr_aton(hostname, &addr)) {
        return hostname;
    }

    char clean[MAX_DNS_NAME];
    bool is_domain = false;

    if (!check_name(hostname, clean, &is_domain)) {
        ZITI_LOG(ERROR, "invalid hostname[%s]", hostname);
    }

    if (is_domain) {
        dns_entry_t *domain = model_map_get(&ziti_dns.domains, clean);
        if (domain == NULL) {
            ZITI_LOG(INFO, "registered wildcard domain[*%s]", clean);
            dns_entry_t *entry = calloc(1, sizeof(dns_entry_t));
            strncpy(entry->name, clean, sizeof(entry->name));
            entry->intercept = intercept;
            model_map_set(&ziti_dns.domains, clean, entry);
        }
        return NULL;
    } else {
        dns_entry_t *entry = model_map_get(&ziti_dns.hostnames, clean);
        if (!entry) {
            entry = new_ipv4_entry(clean);
            entry->intercept = intercept;
        }
        return entry->ip;
    }
}

static const char DNS_OPT[] = { 0x0, 0x0, 0x29, 0x02, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

#define DNS_NO_ERROR 0
#define DNS_NXDOMAIN 3
#define DNS_NOT_IMPL 4


#define DNS_ID(p) (p[0] << 8 | p[1])
#define DNS_FLAGS(p) (p[2] << 8 | p[3])
#define DNS_QRS(p) (p[4] << 8 | p[5])
#define DNS_QR(p) (p + 12)

#define DNS_SET_CODE(p,c) (p[3] = p[3] | (c & 0xf))
#define DNS_SET_ANS(p) (p[2] = p[2] | 0x80)
#define DNS_SET_ARS(p,n) do{ p[6] = n >> 8; p[7] = n & 0xff; } while(0)
#define DNS_SET_AARS(p,n) do{ p[10] = n >> 8; p[11] = n & 0xff; } while(0)

#define IS_QUERY(flags) ((flags & (1 << 15)) == 0)


static void fallback_work(uv_work_t *work_req) {
    struct dns_req *f_req = work_req->data;
    f_req->code = f_req->fallback(f_req->host, f_req->fb_ctx, &f_req->addr);
}

static void dns_work_complete(uv_work_t *work_req, int status) {
    struct dns_req *req = work_req->data;
    if (req->clt != NULL) {
        LIST_REMOVE(req, _next);

        uint8_t *rp = req->rp;
        DNS_SET_CODE(req->resp, req->code);
        if (req->code == DNS_NO_ERROR) {
            ZITI_LOG(TRACE, "found record for host[%s]", req->host);
            DNS_SET_ARS(req->resp, 1);

            // name ref
            *rp++ = 0xc0;
            *rp++ = 0x0c;

            // type A
            *rp++ = 0;
            *rp++ = 1;

            // class IN
            *rp++ = 0;
            *rp++ = 1;

            // TTL
            *rp++ = 0;
            *rp++ = 0;
            *rp++ = 0;
            *rp++ = 255;

            // size 4
            *rp++ = 0;
            *rp++ = sizeof(req->addr.s_addr);

            memcpy(rp, &req->addr.s_addr, sizeof(req->addr.s_addr));
            rp += sizeof(req->addr.s_addr);
        } else {
            DNS_SET_ARS(req->resp, 0);
        }

        DNS_SET_AARS(req->resp, 1);
        memcpy(rp, DNS_OPT, sizeof(DNS_OPT));
        rp += sizeof(DNS_OPT);

        ziti_tunneler_write(req->clt->io_ctx->tnlr_io, req->resp, rp - req->resp);
    } else {
        ZITI_LOG(DEBUG, "DNS request[%s] completed for closed client", req->host);
    }
    free(req);
    free(work_req);
}

ssize_t on_dns_req(void *ziti_io_ctx, void *write_ctx, const uint8_t *q_packet, size_t q_len) {
    struct dns_req *req = calloc(1, sizeof(struct dns_req));
    req->clt = ziti_io_ctx;
    LIST_INSERT_HEAD(&req->clt->active_reqs, req, _next);

    uv_work_t *work_req = calloc(1, sizeof(uv_work_t));
    work_req->data = req;

    memcpy(req->resp, q_packet, 12); // DNS header
    DNS_SET_ANS(req->resp);
    uint8_t *rp = req->resp + 12;

    uint16_t flags = DNS_FLAGS(q_packet);
    uint16_t qrrs = DNS_QRS(q_packet);

    ZITI_LOG(TRACE, "received DNS query q_len=%zd id(%04x) flags(%04x)", q_len, DNS_ID(q_packet), DNS_FLAGS(q_packet));

    if (!IS_QUERY(flags) || qrrs != 1) {
        DNS_SET_ARS(req->resp, 0);
        DNS_SET_AARS(req->resp, 0);
        DNS_SET_CODE(req->resp, DNS_NOT_IMPL);
        req->code = DNS_NOT_IMPL;

        goto DONE;
    }

    char *hp = req->host;
    const uint8_t *q = DNS_QR(q_packet);

    // read query section -- copy into response and construct hostname
    while (*q != 0) {
        int seg_len = *q;

        *rp++ = seg_len;
        q++;
        for (int i = 0; i < seg_len; i++) {
            *rp++ = *q;
            *hp++ = tolower(*q++);
        }
        *hp++ = '.';
    }
    hp--;
    *hp = '\0';
    *rp++ = *q++;

    uint16_t type = (q[0] << 8) | (q[1]); *rp++ = *q++; *rp++ = *q++;
    uint16_t class = (q[0] << 8) | q[1]; *rp++ = *q++; *rp++ = *q++;

    req->rp = rp;

    ZITI_LOG(TRACE, "received query for %s type(%x) class(%x)", req->host, type, class);

    dns_entry_t *entry = ziti_dns_lookup(req->host);
    if (!entry && ziti_dns.fallback_cb) {
        req->fb_ctx = ziti_dns.fallback_ctx;
        req->fallback = ziti_dns.fallback_cb;

        ziti_tunneler_ack(write_ctx);
        return uv_queue_work(ziti_dns.loop, work_req, fallback_work, dns_work_complete);
    }

    if (entry) {
        req->addr.s_addr = entry->addr.u_addr.ip4.addr;
        req->code = DNS_NO_ERROR;
    } else {
        req->code = DNS_NXDOMAIN;
    }

    DONE:
    ziti_tunneler_ack(write_ctx);
    dns_work_complete(work_req, 0);

    return q_len;
}
