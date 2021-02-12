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

static int apply_dns(dns_manager *msg, const char *host, const char *ip);
static int query_dns(dns_manager *dns, const uint8_t *q_packet, size_t q_len, uint8_t **r_packet, size_t *r_len);

struct dns_record {
    struct in_addr ip;
};

struct dns_store {
    model_map map;
};

dns_manager* get_tunneler_dns(uint32_t dns_ip) {
    dns_manager *mgr = calloc(1, sizeof(dns_manager));
    mgr->dns_ip = dns_ip;
    mgr->dns_port = 53;
    mgr->internal_dns = true;

    mgr->apply = apply_dns;
    mgr->query = query_dns;
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

static int query_dns(dns_manager *dns, const uint8_t *q_packet, size_t q_len, uint8_t **r_packet, size_t *r_len) {

    uint8_t *resp = calloc(512, 1);
    memcpy(resp, q_packet, 12); // DNS header
    DNS_SET_ANS(resp);
    uint8_t *rp = resp + 12;

    uint16_t flags = DNS_FLAGS(q_packet);
    uint16_t qrrs = DNS_QRS(q_packet);

    ZITI_LOG(TRACE, "received DNS query q_len=%zd id(%04x) flags(%04x)", q_len, DNS_ID(q_packet), DNS_FLAGS(q_packet));

    if (!IS_QUERY(flags) || qrrs != 1) {
        DNS_SET_ARS(resp, 0);
        DNS_SET_AARS(resp, 0);
        DNS_SET_CODE(resp, DNS_NOT_IMPL);

        goto DONE;
    }

    char host[255];
    char *hp = host;
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

    ZITI_LOG(TRACE, "received query for %s type(%x) class(%x)", host, type, class);

    struct dns_store *store = dns->data;
    struct dns_record *rec = (type == 1) ? model_map_get(&store->map, host) : NULL;
    if (rec) {
        ZITI_LOG(TRACE, "found record for host[%s]", host);
        DNS_SET_ARS(resp, 1);
        DNS_SET_CODE(resp, DNS_NO_ERROR);

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
        *rp++ = 4;

        memcpy(rp, &rec->ip.s_addr, 4);
        rp += 4;
    } else {
        DNS_SET_CODE(resp, DNS_NXDOMAIN);
        DNS_SET_ARS(resp, 0);
    }

    DONE:

    DNS_SET_AARS(resp, 1);
    memcpy(rp, DNS_OPT, sizeof(DNS_OPT));
    rp += sizeof(DNS_OPT);

    *r_len = rp - resp;
    *r_packet = resp;

    return 0;
}
