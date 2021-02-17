/*
Copyright 2021 NetFoundry, Inc.

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

#include <ziti/model_support.h>
#include <ziti/ziti_tunnel.h>
#include <ziti/ziti_log.h>
#include <string.h>
#include <ctype.h>

const char DNS_OPT[] = { 0x0, 0x0, 0x29, 0x02, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

static int apply_dns(dns_manager *mgr, const char *host, const char *ip);
static int query_dns(dns_manager *dns, const uint8_t *q_packet, size_t q_len, dns_answer_cb r_packet, void *r_len);

struct dns_record {
    struct in_addr ip;
};

struct dns_store {
    model_map map;
};

dns_manager* get_tunneler_dns(uv_loop_t *l, uint32_t dns_ip, fallback_cb fb_cb, void *ctx) {
    dns_manager *mgr = calloc(1, sizeof(dns_manager));
    mgr->dns_ip = dns_ip;
    mgr->dns_port = 53;
    mgr->internal_dns = true;

    mgr->apply = apply_dns;
    mgr->query = query_dns;

    mgr->loop = l;
    mgr->fb_cb = fb_cb;
    mgr->fb_ctx = ctx;
    mgr->data = calloc(1, sizeof(struct dns_store));

    return mgr;
}

static int apply_dns(dns_manager *mgr, const char *host, const char *ip) {
    ZITI_LOG(DEBUG, "received DNS record: %s(%s)", host, ip);
    char hostname[256];
    const char *r = host;
    char *p = hostname;
    while (*r) {
        *p++ = (char)tolower(*r++);
    }
    *p = '\0';

    struct dns_record *rec = calloc(1, sizeof(struct dns_record));
    inet_aton(ip, &rec->ip);
    struct dns_record *old = model_map_set(mgr->data, hostname, rec);
    if (old) {
        free(old);
    }

    return 0;
}

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

struct dns_req {
    char host[255];
    fallback_cb fallback;
    void *fb_ctx;

    struct in_addr addr;
    int code;

    uint8_t resp[512];
    uint8_t *rp;
    dns_answer_cb cb;
    void *cb_ctx;
};

void fallback_work(uv_work_t *work_req) {
    struct dns_req *f_req = work_req->data;
    f_req->code = f_req->fallback(f_req->host, f_req->fb_ctx, &f_req->addr);
}

void dns_work_complete(uv_work_t *work_req, int status) {

    ZITI_LOG(INFO, "DNS complete: %d", status);
    struct dns_req *req = work_req->data;

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

    req->cb(req->resp, rp - req->resp, req->cb_ctx);

    free(req);
    free(work_req);
}

static int query_dns(dns_manager *dns, const uint8_t *q_packet, size_t q_len, dns_answer_cb cb, void *ctx) {

    struct dns_req *req = calloc(1, sizeof(struct dns_req));
    req->cb = cb;
    req->cb_ctx = ctx;

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

    struct dns_store *store = dns->data;
    struct dns_record *rec = (type == 1) ? model_map_get(&store->map, req->host) : NULL;

    if (!rec && dns->fb_cb) {
        req->fb_ctx = dns->fb_ctx;
        req->fallback = dns->fb_cb;

        return uv_queue_work(dns->loop, work_req, fallback_work, dns_work_complete);
    }

    if (rec) {
        req->addr.s_addr = rec->ip.s_addr;
        req->code = DNS_NO_ERROR;
    } else {
        req->code = DNS_NXDOMAIN;
    }

    DONE:
    dns_work_complete(work_req, 0);
    return 0;
}
