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
    LIST_HEAD(reqs, dns_req) active_reqs;
} ziti_dns_client_t;

struct dns_req {
    uint16_t id;
    size_t req_len;
    uint8_t req[512];
    size_t resp_len;
    uint8_t resp[512];

    char host[255];
    uint16_t q_class;
    uint16_t q_type;

    struct in_addr addr;
    int code;
    int rr_count;

    uint8_t *rp;

    ziti_dns_client_t *clt;
    LIST_ENTRY(dns_req) _next;
};

static void* on_dns_client(const void *app_intercept_ctx, io_ctx_t *io);
static int on_dns_close(void *dns_io_ctx);
static ssize_t on_dns_req(void *ziti_io_ctx, void *write_ctx, const uint8_t *q_packet, size_t len);
static void query_upstream(struct dns_req *req);
static void udp_alloc(uv_handle_t *h, unsigned long reqlen, uv_buf_t *b);
static void on_upstream_packet(uv_udp_t *h, ssize_t rc, const uv_buf_t *buf, const struct sockaddr* addr, unsigned int flags);
static void complete_dns_req(struct dns_req *req);

typedef struct dns_domain_s {
    char name[MAX_DNS_NAME];

    model_map intercepts; // set[intercept]
    // TODO future
//    model_map resolv_cache;
//    ziti_connection resolv_proxy;
//    bool connected;

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
    } ip_pool;

    // map[hostname -> dns_entry_t]
    model_map hostnames;

    // map[ip_addr_t -> dns_entry_t]
    model_map ip_addresses;

    // map[domain -> dns_domain_t]
    model_map domains;

    uv_loop_t *loop;
    tunneler_context tnlr;

    model_map requests;
    uv_udp_t upstream;
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

    ziti_dns.ip_pool.counter_mask = ~( (uint32_t)-1 << (32 - (uint32_t)bits));
    ziti_dns.ip_pool.base = mask & ~ziti_dns.ip_pool.counter_mask;

    ziti_dns.ip_pool.counter = 10;

    union ip_bits {
        uint8_t b[4];
        uint32_t ip;
    } min_ip, max_ip;

    min_ip.ip = htonl(ziti_dns.ip_pool.base);
    max_ip.ip = htonl(ziti_dns.ip_pool.base | ziti_dns.ip_pool.counter_mask);
    ZITI_LOG(INFO, "DNS configured with range %d.%d.%d.%d - %d.%d.%d.%d",
             min_ip.b[0],min_ip.b[1],min_ip.b[2],min_ip.b[3],
             max_ip.b[0],max_ip.b[1],max_ip.b[2],max_ip.b[3]
             );

    return 0;
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
    }

    if (port == 0) port = 53;

    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%d", port);
    uv_getaddrinfo_t req = {0};
    CHECK_UV(uv_getaddrinfo(l, &req, NULL, host, port_str, NULL));
    CHECK_UV(uv_udp_connect(&ziti_dns.upstream, req.addrinfo->ai_addr));
    CHECK_UV(uv_udp_recv_start(&ziti_dns.upstream, udp_alloc, on_upstream_packet));
    ZITI_LOG(INFO, "DNS upstream is set to %s:%d", host, port);
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
    entry->addr.type = IPADDR_TYPE_V4;
    entry->addr.u_addr.ip4.addr = next_ipv4();
    ip4addr_ntoa_r(&entry->addr.u_addr.ip4, entry->ip, sizeof(entry->ip));

    model_map_set(&ziti_dns.hostnames, host, entry);
    model_map_set_key(&ziti_dns.ip_addresses, &entry->addr, sizeof(entry->addr), entry);
    ZITI_LOG(INFO, "registered DNS entry %s -> %s", host, entry->ip);

    return entry;
}

const char *ziti_dns_reverse_lookup_domain(const ip_addr_t *addr) {
     dns_entry_t *entry = model_map_get_key(&ziti_dns.ip_addresses, addr, sizeof(*addr));
     if (entry && entry->domain) {
         return entry->domain->name;
     }
     return NULL;
}

const char *ziti_dns_reverse_lookup(const char *ip_addr) {
    ip_addr_t addr = {0};
    ipaddr_aton(ip_addr, &addr);
    dns_entry_t *entry = model_map_get_key(&ziti_dns.ip_addresses, &addr, sizeof(addr));

    return entry ? entry->name : NULL;
}

dns_entry_t *ziti_dns_lookup(const char *hostname) {
    char clean[MAX_DNS_NAME];
    bool is_wildcard;
    if (!check_name(hostname, clean, &is_wildcard) || is_wildcard) {
        ZITI_LOG(WARN, "invalid host lookup[%s]", hostname);
        return NULL;
    }

    dns_entry_t *entry = model_map_get(&ziti_dns.hostnames, clean);
    if (entry) {
        return entry;
    }

    // try domains
    char *dot = strchr(clean, '.');
    while (dot != NULL) {
        dns_domain_t *domain = model_map_get(&ziti_dns.domains, dot + 1);
        if (domain) {
            ZITI_LOG(DEBUG, "matching domain[%s] found for %s", domain->name, hostname);
            dns_entry_t *host_entry = new_ipv4_entry(clean);
            host_entry->domain = domain;
            return host_entry;
        }
        dot = strchr(dot + 1, '.');
    }
    return NULL;
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
            it = model_map_it_remove(it);
            model_map_remove(&ziti_dns.ip_addresses, e->ip);
            ZITI_LOG(INFO, "removed DNS mapping %s -> %s", e->name, e->ip);
            free(e);
        } else {
            it = model_map_it_next(it);
        }
    }

    it = model_map_iterator(&ziti_dns.domains);
    while (it != NULL) {
        dns_domain_t *domain = model_map_it_value(it);
        if (model_map_size(&domain->intercepts) == 0) {
            it = model_map_it_remove(it);
            ZITI_LOG(INFO, "removed wildcard domain[*%s]", domain->name);
            free_domain(domain);
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
        model_map_set_key(&entry->intercepts, &intercept, sizeof(intercept), intercept);
        return entry->ip;
    }
}

static const char DNS_OPT[] = { 0x0, 0x0, 0x29, 0x02, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };


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

#define IS_QUERY(flags) (((flags) & (1 << 15)) == 0)

static void format_resp(struct dns_req *req) {

    uint8_t *rp = req->rp;
    DNS_SET_CODE(req->resp, req->code);
    if (req->code == DNS_NO_ERROR && req->rr_count > 0) {
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
    req->resp_len = rp - req->resp;
}

ssize_t on_dns_req(void *ziti_io_ctx, void *write_ctx, const uint8_t *q_packet, size_t q_len) {
    struct dns_req *req = calloc(1, sizeof(struct dns_req));
    req->clt = ziti_io_ctx;
    LIST_INSERT_HEAD(&req->clt->active_reqs, req, _next);

    bool recursion_avail = uv_is_active((const uv_handle_t *) &ziti_dns.upstream);

    uint16_t flags = DNS_FLAGS(q_packet);
    uint16_t qrrs = DNS_QRS(q_packet);
    int recursive = DNS_RD(q_packet);

    req->id = DNS_ID(q_packet);
    req->req_len = q_len;
    memcpy(req->req, q_packet, q_len);
    model_map_setl(&ziti_dns.requests, (long)req->id, req);
    ZITI_LOG(TRACE, "received DNS query q_len=%zd id[%04x] flags[%04x] recursive[%s]", q_len, req->id, flags, recursive ? "true" : "false");

    memcpy(req->resp, q_packet, 12); // DNS header
    DNS_SET_ANS(req->resp);
    if (recursion_avail) {
        DNS_SET_RA(req->resp);
    }
    DNS_SET_ARS(req->resp, 0);
    DNS_SET_AARS(req->resp, 0);
    DNS_SET_CODE(req->resp, DNS_NO_ERROR);

    uint8_t *rp = req->resp + 12;

    if (!IS_QUERY(flags) || qrrs != 1) {
        DNS_SET_ARS(req->resp, 0);
        DNS_SET_AARS(req->resp, 0);
        DNS_SET_CODE(req->resp, DNS_NOT_IMPL);
        req->code = DNS_NOT_IMPL;
        complete_dns_req(req);
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
            *hp++ = (char)tolower(*q++);
        }
        *hp++ = '.';
    }
    hp--;
    *hp = '\0';
    *rp++ = *q++;

    req->q_type = (q[0] << 8) | (q[1]); *rp++ = *q++; *rp++ = *q++;
    req->q_class = (q[0] << 8) | q[1]; *rp++ = *q++; *rp++ = *q++;

    ZITI_LOG(TRACE, "received query for %s type(%x) class(%x)", req->host, req->q_type, req->q_class);
    if (req->q_class != 1) {
        DNS_SET_ARS(req->resp, 0);
        DNS_SET_AARS(req->resp, 0);
        DNS_SET_CODE(req->resp, DNS_NOT_IMPL);
        req->code = DNS_NOT_IMPL;
        complete_dns_req(req);
        goto DONE;
    }

    req->rp = rp;

    if (req->q_type == NS_T_A || req->q_type == NS_T_AAAA) {
        dns_entry_t *entry = ziti_dns_lookup(req->host);
        if (entry) {
            req->code = DNS_NO_ERROR;
            if (req->q_type == NS_T_A) {
                req->rr_count = 1;
                req->addr.s_addr = entry->addr.u_addr.ip4.addr;
            } else {
                DNS_SET_ARS(req->resp, 0);
                DNS_SET_AARS(req->resp, 0);
                DNS_SET_CODE(req->resp, DNS_NO_ERROR);
                req->rr_count = 0;
            }
            format_resp(req);
        } else  {
            if (recursive && recursion_avail) {
                query_upstream(req);
                goto DONE;
            }
        }
    }

    // future proxy lookup for (MX, TXT, SRV)
    complete_dns_req(req);

    DONE:
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

void query_upstream(struct dns_req *req) {
    int rc;
    uv_udp_send_t *sr = calloc(1, sizeof(uv_udp_send_t));
    sr->data = req;
    uv_buf_t buf = uv_buf_init((char*)req->req, req->req_len);
    if ((rc = uv_udp_send(sr, &ziti_dns.upstream, &buf, 1, NULL, on_upstream_send)) != 0) {
        ZITI_LOG(WARN, "failed to query[%04x] upstream DNS server: %d(%s)", req->id, rc, uv_strerror(rc));
    }
}

static void udp_alloc(uv_handle_t *h, unsigned long reqlen, uv_buf_t *b) {
    b->base = malloc(1024);
    b->len = 1024;
}

static void on_upstream_packet(uv_udp_t *h, ssize_t rc, const uv_buf_t *buf, const struct sockaddr* addr, unsigned int flags) {
    if (rc > 0) {
        uint16_t id = DNS_ID(buf->base);
        struct dns_req *req = model_map_getl(&ziti_dns.requests, id);
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

static void complete_dns_req(struct dns_req *req) {
    model_map_removel(&ziti_dns.requests, req->id);
    if (req->clt) {
        ziti_tunneler_write(req->clt->io_ctx->tnlr_io, req->resp, req->resp_len);
        LIST_REMOVE(req, _next);
    } else {
        ZITI_LOG(WARN, "query[%04x] is stale", req->id);
    }

    free(req);
}

static void free_domain(dns_domain_t *domain) {
//    model_map_clear(&domain->resolv_cache, NULL);
//    ziti_close(domain->resolv_proxy, NULL);
    free(domain);
}