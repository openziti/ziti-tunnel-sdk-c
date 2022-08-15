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
#include "dns_host.h"

#define MAX_DNS_NAME 256
#define MAX_IP_LENGTH 16

enum ns_q_type {
    NS_T_A = 1,
    NS_T_AAAA = 28,
    NS_T_MX = 15,
    NS_T_TXT = 16,
    NS_T_SRV = 33,
};

typedef struct ziti_dns_client_s {
    io_ctx_t *io_ctx;
    bool is_tcp;
    LIST_HEAD(reqs, dns_req) active_reqs;
} ziti_dns_client_t;

struct dns_req {
    uint16_t id;
    size_t req_len;
    uint8_t req[512];
    size_t resp_len;
    uint8_t resp[512];

    dns_message msg;

    struct in_addr addr;

    uint8_t *rp;

    ziti_dns_client_t *clt;
    LIST_ENTRY(dns_req) _next;
};

static void* on_dns_client(const void *app_intercept_ctx, io_ctx_t *io);
static int on_dns_close(void *dns_io_ctx);
static ssize_t on_dns_req(void *ziti_io_ctx, void *write_ctx, const void *q_packet, size_t len);
static int query_upstream(struct dns_req *req);
static void udp_alloc(uv_handle_t *h, unsigned long reqlen, uv_buf_t *b);
static void on_upstream_packet(uv_udp_t *h, ssize_t rc, const uv_buf_t *buf, const struct sockaddr* addr, unsigned int flags);
static void complete_dns_req(struct dns_req *req);
static void free_dns_req(struct dns_req *req);

typedef struct dns_domain_s {
    char name[MAX_DNS_NAME];

    model_map intercepts; // set[intercept]

    ziti_connection resolv_proxy;

} dns_domain_t;

static void free_domain(dns_domain_t *domain);


// hostname or domain
typedef struct dns_entry_s {
    char name[MAX_DNS_NAME];
    char ip[MAX_IP_LENGTH];
    ip_addr_t addr;
    dns_domain_t *domain;

    model_map intercepts;

} dns_entry_t;

struct ziti_dns_s {

    struct {
        uint32_t base;
        uint32_t counter;
        uint32_t counter_mask;
        uint32_t capacity;
    } ip_pool;

    // map[hostname -> dns_entry_t]
    model_map hostnames;

    // map[ip4_addr_t -> dns_entry_t]
    model_map ip_addresses;

    // map[domain -> dns_domain_t]
    model_map domains;

    uv_loop_t *loop;
    tunneler_context tnlr;

    model_map requests;
    uv_udp_t upstream;
    struct sockaddr upstream_addr;
} ziti_dns;

static uint32_t next_ipv4() {
    uint32_t candidate;
    uint32_t i = 0; // track how many candidates have been considered. should never exceed pool capacity.

    if (model_map_size(&ziti_dns.ip_addresses) == ziti_dns.ip_pool.capacity) {
        ZITI_LOG(ERROR, "DNS ip pool exhausted (%u IPs). Try rerunning with larger DNS range.",
                 ziti_dns.ip_pool.capacity);
        return INADDR_NONE;
    }

    do {
        candidate = htonl(ziti_dns.ip_pool.base | (ziti_dns.ip_pool.counter++ & ziti_dns.ip_pool.counter_mask));
        i += 1;
        if (ziti_dns.ip_pool.counter == ziti_dns.ip_pool.counter_mask) {
            ziti_dns.ip_pool.counter = 1;
        }
    } while ((model_map_getl(&ziti_dns.ip_addresses, candidate) != NULL) && i < ziti_dns.ip_pool.capacity);

    if (i == ziti_dns.ip_pool.capacity) {
        ZITI_LOG(ERROR, "no IPs available after scanning entire pool");
        return INADDR_NONE;
    }

    return candidate;
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

    ziti_dns.ip_pool.counter_mask = ~( (uint32_t)-1 << (32 - (uint32_t)bits));
    ziti_dns.ip_pool.base = mask & ~ziti_dns.ip_pool.counter_mask;

    ziti_dns.ip_pool.counter = 1;
    ziti_dns.ip_pool.capacity = (1 << (32 - bits)) - 2; // subtract 2 for network and broadcast IPs

    union ip_bits {
        uint8_t b[4];
        uint32_t ip;
    } min_ip, max_ip;

    min_ip.ip = htonl(ziti_dns.ip_pool.base);
    max_ip.ip = htonl(ziti_dns.ip_pool.base | ziti_dns.ip_pool.counter_mask);
    ZITI_LOG(INFO, "DNS configured with range %d.%d.%d.%d - %d.%d.%d.%d (%u ips)",
             min_ip.b[0],min_ip.b[1],min_ip.b[2],min_ip.b[3],
             max_ip.b[0],max_ip.b[1],max_ip.b[2],max_ip.b[3], ziti_dns.ip_pool.capacity
             );

    return 0;
}

int ziti_dns_setup(tunneler_context tnlr, const char *dns_addr, const char *dns_cidr) {
    ziti_dns.tnlr = tnlr;
    seed_dns(dns_cidr);

    intercept_ctx_t *dns_intercept = intercept_ctx_new(tnlr, "ziti:dns-resolver", &ziti_dns);
    ziti_address dns_zaddr, tun_zaddr;
    ziti_address_from_string(&dns_zaddr, dns_addr);
    intercept_ctx_add_address(dns_intercept, &dns_zaddr);
    intercept_ctx_add_port_range(dns_intercept, 53, 53);
    intercept_ctx_add_protocol(dns_intercept, "udp");
    intercept_ctx_override_cbs(dns_intercept, on_dns_client, on_dns_req, on_dns_close, on_dns_close);
    ziti_tunneler_intercept(tnlr, dns_intercept);

    // reserve tun and dns ips by adding to ip_addresses with empty dns entries
    ziti_address_from_string(&tun_zaddr, dns_cidr); // assume tun ip is first in dns_cidr
    ziti_address *reserved[] = { &tun_zaddr, &dns_zaddr };
    size_t n = sizeof(reserved) / sizeof(ziti_address *);
    for (int i = 0; i < n; i++) {
        ip_addr_t ip4;
        struct in_addr *in4_p = (struct in_addr *) &reserved[i]->addr.cidr.ip;
        model_map_setl(&ziti_dns.ip_addresses, in4_p->s_addr, calloc(1, sizeof(dns_entry_t)));
    }
    return 0;
}

#define CHECK_UV(op) do{ int rc = (op); if (rc < 0) {\
ZITI_LOG(ERROR, "failed [" #op "]: %d(%s)", rc, uv_strerror(rc)); \
return rc;} \
}while(0)

int ziti_dns_set_upstream(uv_loop_t *l, const char *host, uint16_t port) {
    if (uv_is_active((const uv_handle_t *) &ziti_dns.upstream)) {
        uv_udp_recv_stop(&ziti_dns.upstream);
        CHECK_UV(uv_udp_connect(&ziti_dns.upstream, NULL));
    } else {
        CHECK_UV(uv_udp_init(l, &ziti_dns.upstream));
        uv_unref((uv_handle_t *) &ziti_dns.upstream);
    }

    if (port == 0) port = 53;

    if (uv_inet_pton(AF_INET6, host, &((struct sockaddr_in6*)&ziti_dns.upstream_addr)->sin6_addr) == 0) {
        ziti_dns.upstream_addr.sa_family = AF_INET6;
        ((struct sockaddr_in6*)&ziti_dns.upstream_addr)->sin6_port = htons(port);
    } else if (uv_inet_pton(AF_INET, host, &((struct sockaddr_in*)&ziti_dns.upstream_addr)->sin_addr) == 0) {
        ziti_dns.upstream_addr.sa_family = AF_INET;
        ((struct sockaddr_in*)&ziti_dns.upstream_addr)->sin_port = htons(port);
    } else {
        ZITI_LOG(WARN, "upstream address[%s] is not IP format", host);
        char port_str[6];
        snprintf(port_str, sizeof(port_str), "%hu", port);
        uv_getaddrinfo_t req = {0};
        CHECK_UV(uv_getaddrinfo(l, &req, NULL, host, port_str, NULL));
        memcpy(&ziti_dns.upstream_addr, req.addrinfo->ai_addr, sizeof(ziti_dns.upstream_addr));
    }
    CHECK_UV(uv_udp_recv_start(&ziti_dns.upstream, udp_alloc, on_upstream_packet));
    CHECK_UV(uv_udp_connect(&ziti_dns.upstream, &ziti_dns.upstream_addr));
    ZITI_LOG(INFO, "DNS upstream is set to %s:%hu", host, port);
    return 0;
}


void* on_dns_client(const void *app_intercept_ctx, io_ctx_t *io) {
    ZITI_LOG(DEBUG, "new DNS client");
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
    return 0;
}

static bool check_name(const char *name, char clean_name[MAX_DNS_NAME], bool *is_domain) {
    const char *hp = name;
    char *p = clean_name;

    if (*hp == '*' && *(hp + 1) == '.') {
        *is_domain = true;
        *p++ = '*';
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
    uint32_t next = next_ipv4();
    if (next == INADDR_NONE) {
        return NULL;
    }

    ip_addr_set_ip4_u32(&entry->addr, next);
    ipaddr_ntoa_r(&entry->addr, entry->ip, sizeof(entry->ip));

    model_map_set(&ziti_dns.hostnames, host, entry);
    model_map_setl(&ziti_dns.ip_addresses, ip_2_ip4(&entry->addr)->addr, entry);
    ZITI_LOG(INFO, "registered DNS entry %s -> %s", host, entry->ip);

    return entry;
}

const char *ziti_dns_reverse_lookup_domain(const ip_addr_t *addr) {
     dns_entry_t *entry = model_map_getl(&ziti_dns.ip_addresses, ip_2_ip4(addr)->addr);
     if (entry && entry->domain) {
         return entry->domain->name;
     }
     return NULL;
}

const char *ziti_dns_reverse_lookup(const char *ip_addr) {
    ip_addr_t addr = {0};
    ipaddr_aton(ip_addr, &addr);
    dns_entry_t *entry = model_map_getl(&ziti_dns.ip_addresses, ip_2_ip4(&addr)->addr);

    return entry ? entry->name : NULL;
}

static dns_domain_t* find_domain(const char *hostname) {
    char *dot = strchr(hostname, '.');
    dns_domain_t *domain = model_map_get(&ziti_dns.domains, hostname);
    while (dot != NULL && domain == NULL) {
        domain = model_map_get(&ziti_dns.domains, dot + 1);
        dot = strchr(dot + 1, '.');
    }
    return domain;
}

static dns_entry_t *ziti_dns_lookup(const char *hostname) {
    char clean[MAX_DNS_NAME];
    bool is_wildcard;
    if (!check_name(hostname, clean, &is_wildcard) || is_wildcard) {
        ZITI_LOG(WARN, "invalid host lookup[%s]", hostname);
        return NULL;
    }

    dns_entry_t *entry = model_map_get(&ziti_dns.hostnames, clean);

    if (!entry) {         // try domains
        dns_domain_t *domain = find_domain(clean);

        if (domain && model_map_size(&domain->intercepts) > 0) {
            ZITI_LOG(DEBUG, "matching domain[%s] found for %s", domain->name, hostname);
            entry = new_ipv4_entry(clean);
            entry->domain = domain;
        }
    }

    if (entry) {
        if (model_map_size(&entry->intercepts) > 0 ||
            (entry->domain && model_map_size(&entry->domain->intercepts) > 0)) {
            return entry;
        } else {
            return NULL; // inactive entry
        }
    }
    return entry;
}


void ziti_dns_deregister_intercept(void *intercept) {
    model_map_iter it = model_map_iterator(&ziti_dns.domains);
    while (it != NULL) {
        dns_domain_t *domain = model_map_it_value(it);
        model_map_remove_key(&domain->intercepts, &intercept, sizeof(intercept));
        it = model_map_it_next(it);
    }

    it = model_map_iterator(&ziti_dns.hostnames);
    while (it != NULL) {
        dns_entry_t *e = model_map_it_value(it);
        model_map_remove_key(&e->intercepts, &intercept, sizeof(intercept));
        if (model_map_size(&e->intercepts) == 0 && (e->domain == NULL || model_map_size(&e->domain->intercepts) == 0)) {
            model_map_remove(&ziti_dns.hostnames, e->name);
            model_map_removel(&ziti_dns.ip_addresses, ip_2_ip4(&e->addr)->addr);
            ZITI_LOG(DEBUG, "%zu active hostnames mapped to %zu IPs", model_map_size(&ziti_dns.hostnames), model_map_size(&ziti_dns.ip_addresses));
            ZITI_LOG(INFO, "DNS mapping %s -> %s is now inactive", e->name, e->ip);
        }
        it = model_map_it_next(it);
    }

    it = model_map_iterator(&ziti_dns.domains);
    while (it != NULL) {
        dns_domain_t *domain = model_map_it_value(it);
        if (model_map_size(&domain->intercepts) == 0) {
            model_map_remove(&ziti_dns.domains, domain->name);
            ZITI_LOG(INFO, "wildcard domain[*%s] is now inactive", domain->name);
        }
        it = model_map_it_next(it);
    }
}

const ip_addr_t *ziti_dns_register_hostname(const ziti_address *addr, void *intercept) {
    // IP or CIDR block
    if (addr->type == ziti_address_cidr) {
        return NULL;
    }

    const char *hostname = addr->addr.hostname;
    char clean[MAX_DNS_NAME];
    bool is_domain = false;

    if (!check_name(hostname, clean, &is_domain)) {
        ZITI_LOG(ERROR, "invalid hostname[%s]", hostname);
    }

    if (is_domain) {
        dns_domain_t *domain = model_map_get(&ziti_dns.domains, clean + 2);
        if (domain == NULL) {
            ZITI_LOG(INFO, "registered wildcard domain[%s]", clean);
            domain = calloc(1, sizeof(dns_domain_t));
            strncpy(domain->name, clean, sizeof(domain->name));
            model_map_set(&ziti_dns.domains, clean + 2, domain);
        }
        model_map_set_key(&domain->intercepts, &intercept, sizeof(intercept), intercept);
        return NULL;
    } else {
        dns_entry_t *entry = model_map_get(&ziti_dns.hostnames, clean);
        if (!entry) {
            entry = new_ipv4_entry(clean);
        }
        if (entry) {
            model_map_set_key(&entry->intercepts, &intercept, sizeof(intercept), intercept);
            return &entry->addr;
        } else {
            return NULL;
        }
    }
}

static const char DNS_OPT[] = { 0x0, 0x0, 0x29, 0x02, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

#define DNS_HEADER_LEN 12
#define DNS_ID(p) ((uint8_t)(p)[0] << 8 | (uint8_t)(p)[1])
#define DNS_FLAGS(p) ((p)[2] << 8 | (p)[3])
#define DNS_QRS(p) ((p)[4] << 8 | (p)[5])
#define DNS_QR(p) ((p) + 12)
#define DNS_RD(p) ((p)[2] & 0x1)

#define DNS_SET_RA(p) ((p)[3] = (p)[3] | 0x80)
#define DNS_SET_CODE(p,c) ((p)[3] = (p)[3] | ((c) & 0xf))
#define DNS_SET_ANS(p) ((p)[2] = (p)[2] | 0x80)
#define DNS_SET_ARS(p,n) do{ (p)[6] = (n) >> 8; (p)[7] = (n) & 0xff; } while(0)
#define DNS_SET_AARS(p,n) do{ (p)[10] = (n) >> 8; (p)[11] = (n) & 0xff; } while(0)

#define SET_U8(p,v) *(p)++ = (v) & 0xff
#define SET_U16(p,v) (*(p)++ = ((v) >> 8) & 0xff),*(p)++ = (v) & 0xff
#define SET_U32(p,v) (*(p)++ = ((v) >> 24) & 0xff), \
(*(p)++ = ((v)>>16) & 0xff),                          \
(*(p)++ = ((v) >> 8) & 0xff),                       \
*(p)++ = (v) & 0xff

#define IS_QUERY(flags) (((flags) & (1 << 15)) == 0)

static uint8_t* format_name(uint8_t* p, const char* name) {
    const char *np = name;
    do {
        const char *dot = strchr(np, '.');
        uint8_t len = dot ? dot - np : strlen(np);

        *p++ = len;
        if (len == 0) break;

        memcpy(p, np, len);
        p += len;

        if (dot == NULL) {
            *p++ = 0;
            break;
        } else {
            np = dot + 1;
        }
    } while(1);
    return p;
}

static void format_resp(struct dns_req *req) {

    // copy header from request
    memcpy(req->resp, req->req, DNS_HEADER_LEN); // DNS header
    DNS_SET_ANS(req->resp);
    DNS_SET_CODE(req->resp, req->msg.status);
    bool recursion_avail = uv_is_active((const uv_handle_t *) &ziti_dns.upstream);
    if (recursion_avail) {
        DNS_SET_RA(req->resp);
    }

    size_t query_section_len = strlen(req->msg.question[0]->name) + 2 + 4;
    memcpy(req->resp + DNS_HEADER_LEN, req->req + DNS_HEADER_LEN, query_section_len);

    uint8_t *rp = req->resp + DNS_HEADER_LEN + query_section_len;

    if (req->msg.status == DNS_NO_ERROR && req->msg.answer != NULL) {
        int ans_count = 0;
        for (int i = 0; req->msg.answer[i] != NULL; i++) {
            ans_count++;
            dns_answer *a = req->msg.answer[i];
            // name ref
            *rp++ = 0xc0;
            *rp++ = 0x0c;

            ZITI_LOG(INFO, "found record[%s] for query[%d:%s]", a->data, req->msg.question[0]->type, req->msg.question[0]->name);

            SET_U16(rp, a->type);
            SET_U16(rp, 1); // class IN
            SET_U32(rp, a->ttl);

            switch (a->type) {
                case NS_T_A: {
                    SET_U16(rp, sizeof(req->addr.s_addr));
                    memcpy(rp, &req->addr.s_addr, sizeof(req->addr.s_addr));
                    rp += sizeof(req->addr.s_addr);
                    break;
                }

                case NS_T_TXT: {
                    uint16_t txtlen = strlen(a->data);
                    uint16_t datalen = 1 + txtlen;
                    SET_U16(rp, datalen);
                    SET_U8(rp, txtlen);
                    memcpy(rp, a->data, txtlen);
                    rp += txtlen;
                    break;
                }
                case NS_T_MX: {
                    uint8_t *hold = rp;
                    rp += 2;
//                    uint16_t datalen = strlen(a->data) + 1 + 2;
//                    SET_U16(rp, datalen);
                    SET_U16(rp, a->priority);
                    rp = format_name(rp, a->data);
                    uint16_t datalen = rp - hold - 2;
                    SET_U16(hold, datalen);
                    break;
                }
                case NS_T_SRV: {
                    uint8_t *hold = rp;
                    rp += 2;
                    SET_U16(rp, a->priority);
                    SET_U16(rp, a->weight);
                    SET_U16(rp, a->port);
                    rp = format_name(rp, a->data);
                    uint16_t datalen = rp - hold - 2;
                    SET_U16(hold, datalen);
                    break;
                }
                default:
                    ZITI_LOG(WARN, "unhandled response type[%d]", a->type);
            }
        }
        DNS_SET_ARS(req->resp, ans_count);
    }

    DNS_SET_AARS(req->resp, 1);
    memcpy(rp, DNS_OPT, sizeof(DNS_OPT));
    rp += sizeof(DNS_OPT);
    req->resp_len = rp - req->resp;
}

static void process_host_req(struct dns_req *req) {
    dns_entry_t *entry = ziti_dns_lookup(req->msg.question[0]->name);
    if (entry) {
        req->msg.status = DNS_NO_ERROR;

        if (req->msg.question[0]->type == NS_T_A) {
            req->addr.s_addr = entry->addr.u_addr.ip4.addr;

            dns_answer *a = calloc(1, sizeof(dns_answer));
            a->ttl = 60;
            a->type = NS_T_A;
            a->data = strdup(entry->ip);
            req->msg.answer = calloc(2, sizeof(dns_answer *));
            req->msg.answer[0] = a;
        }

        format_resp(req);
        complete_dns_req(req);
    } else {
        int rc = query_upstream(req);
        if (rc != DNS_NO_ERROR) {
            req->msg.status = rc;
            format_resp(req);
            complete_dns_req(req);
        }
    }
}


static void on_proxy_connect(ziti_connection conn, int status) {
    dns_domain_t *domain = ziti_conn_data(conn);
    if (status == ZITI_OK) {
        ZITI_LOG(INFO, "proxy resolve connection established for domain[%s]", domain->name);
    } else {
        ZITI_LOG(ERROR, "failed to establish proxy resolve connection for domain[%s]", domain->name);
        domain->resolv_proxy = NULL;
        ziti_close(conn, NULL);
    }
}

static ssize_t on_proxy_data(ziti_connection conn, uint8_t* data, ssize_t status) {
    if (status >= 0) {
        ZITI_LOG(INFO, "proxy resolve: %.*s", (int)status, data);
        dns_message msg = {0};
        int rc = parse_dns_message(&msg, data, status);
        if (rc < 0) {

            return rc;
        }
        uint16_t id = msg.id;
        struct dns_req *req = model_map_get_key(&ziti_dns.requests, &id, sizeof(id));
        if (req) {
            req->msg.answer = msg.answer;
            msg.answer = NULL;
            format_resp(req);
            complete_dns_req(req);
        }
        free_dns_message(&msg);
    } else {
        ZITI_LOG(ERROR, "proxy resolve connection failed: %d(%s)", (int)status, ziti_errorstr(status));

        dns_domain_t *domain = ziti_conn_data(conn);
        domain->resolv_proxy = NULL;
        ziti_close(conn, NULL);
    }
    return status;
}

static void on_proxy_write(ziti_connection conn, ssize_t status, void *ctx) {
    ZITI_LOG(INFO, "proxy resolve write: %d", (int)status);
    free(ctx);
}

static void proxy_domain_req(struct dns_req *req, dns_domain_t *domain) {
    if (domain->resolv_proxy == NULL) {
        model_map_iter it = model_map_iterator(&domain->intercepts);
        void *intercept = model_map_it_value(it);

        domain->resolv_proxy = intercept_resolve_connect(intercept, domain, on_proxy_connect, on_proxy_data);
    }

    size_t jsonlen;
    char *json = dns_message_to_json(&req->msg, 0, &jsonlen);
    ZITI_LOG(INFO, "writing proxy resolve [%s]", json);
    ziti_write(domain->resolv_proxy, json, jsonlen, on_proxy_write, json);
}


ssize_t on_dns_req(void *ziti_io_ctx, void *write_ctx, const void *q_packet, size_t q_len) {
    ziti_dns_client_t *clt = ziti_io_ctx;
    const uint8_t *dns_packet = q_packet;
    size_t dns_packet_len = q_len;

    uint16_t req_id = DNS_ID(dns_packet);
    struct dns_req *req = model_map_get_key(&ziti_dns.requests, &req_id, sizeof(req_id));
    if (req != NULL) {
        ZITI_LOG(TRACE, "duplicate dns req[%04x] from %s client", req_id, req->clt == ziti_io_ctx ? "same" : "another");
        // just drop new request
        ziti_tunneler_ack(write_ctx);
        return (ssize_t)q_len;
    }

    req = calloc(1, sizeof(struct dns_req));
    req->clt = ziti_io_ctx;

    req->req_len = q_len;
    memcpy(req->req, q_packet, q_len);

    if (parse_dns_req(&req->msg, dns_packet, dns_packet_len) != 0) {
        ZITI_LOG(ERROR, "failed to parse DNS message");
        on_dns_close(clt);
        free_dns_req(req);
        free(write_ctx);
        return (ssize_t)q_len;
    }
    req->id = req->msg.id;

    ZITI_LOG(TRACE, "received DNS query q_len=%zd id[%04x] recursive[%s] type[%d] name[%s]", q_len, req->id,
             req->msg.recursive ? "true" : "false",
             req->msg.question[0]->type,
             req->msg.question[0]->name);

    LIST_INSERT_HEAD(&req->clt->active_reqs, req, _next);
    model_map_set_key(&ziti_dns.requests, &req->id, sizeof(req->id), req);

    // route request
    dns_question *q = req->msg.question[0];

    if (q->type == NS_T_A || q->type == NS_T_AAAA) {
        process_host_req(req);
    } else {
        dns_domain_t *domain = find_domain(q->name);
        if (domain) {
            proxy_domain_req(req, domain);
        } else {
            int dns_status = query_upstream(req);
            if (dns_status != DNS_NO_ERROR) {
                req->msg.status = dns_status;
                format_resp(req);
                complete_dns_req(req);
            }
        }
    }

    ziti_tunneler_ack(write_ctx);
    return (ssize_t)q_len;
}

static void on_upstream_send(uv_udp_send_t *sr, int rc) {
    struct dns_req *req = sr->data;
    if (rc < 0) {
        ZITI_LOG(WARN, "failed to query[%04x] upstream DNS server: %d(%s)", req->id, rc, uv_strerror(rc));
    }
    free(sr);
}

int query_upstream(struct dns_req *req) {
    bool avail = uv_is_active((const uv_handle_t *) &ziti_dns.upstream);
    int rc = -1;
    uv_udp_send_t *sr = NULL;

    if (avail) {
        sr = calloc(1, sizeof(uv_udp_send_t));
        sr->data = req;
        uv_buf_t buf = uv_buf_init((char *) req->req, req->req_len);
        if ((rc = uv_udp_send(sr, &ziti_dns.upstream, &buf, 1, NULL, on_upstream_send)) != 0) {
            ZITI_LOG(WARN, "failed to query[%04x] upstream DNS server: %d(%s)", req->id, rc, uv_strerror(rc));
            uv_udp_connect(&ziti_dns.upstream, NULL);
            rc = uv_udp_connect(&ziti_dns.upstream, &ziti_dns.upstream_addr);
            if (rc == 0) {
                ZITI_LOG(INFO, "dns upstream re-connected successfully");
                rc = uv_udp_send(sr, &ziti_dns.upstream, &buf, 1, NULL, on_upstream_send);
                if (rc != 0) {
                    ZITI_LOG(WARN, "failed again to query[%04x] upstream DNS server: %d(%s)", req->id, rc, uv_strerror(rc));
                }
            } else {
                ZITI_LOG(WARN, "failed to reconnect upstream: %d/%s", rc, uv_strerror(rc));
            }
        }
    }
    if (rc != 0 && sr != NULL) free(sr);
    return rc == 0 ? DNS_NO_ERROR : DNS_REFUSE;
}

static void udp_alloc(uv_handle_t *h, unsigned long reqlen, uv_buf_t *b) {
    b->base = malloc(1024);
    b->len = 1024;
}

static void on_upstream_packet(uv_udp_t *h, ssize_t rc, const uv_buf_t *buf, const struct sockaddr* addr, unsigned int flags) {
    if (rc > 0) {
        uint16_t id = DNS_ID(buf->base);
        struct dns_req *req = model_map_get_key(&ziti_dns.requests, &id, sizeof(id));
        if (req == NULL) {
            ZITI_LOG(WARN, "got response for unknown query[%04x] (rc=%zd)", id, rc);
        } else {
            ZITI_LOG(TRACE, "upstream sent response to query[%04x] (rc=%zd)", id, rc);
            if (rc <= sizeof(req->resp)) {
                req->resp_len = rc;
                memcpy(req->resp, buf->base, rc);
            } else {
                ZITI_LOG(WARN, "unexpected DNS response: too large");
            }
            complete_dns_req(req);
        }
    }
    free(buf->base);
}
static void free_dns_req(struct dns_req *req) {
    free_dns_message(&req->msg);
    free(req);
}

static void complete_dns_req(struct dns_req *req) {
    model_map_remove_key(&ziti_dns.requests, &req->id, sizeof(req->id));
    if (req->clt) {
        ziti_tunneler_write(req->clt->io_ctx->tnlr_io, req->resp, req->resp_len);
        LIST_REMOVE(req, _next);
    } else {
        ZITI_LOG(WARN, "query[%04x] is stale", req->id);
    }
    free_dns_req(req);
}

static void free_domain(dns_domain_t *domain) {
//    model_map_clear(&domain->resolv_cache, NULL);
//    ziti_close(domain->resolv_proxy, NULL);
    free(domain);
}