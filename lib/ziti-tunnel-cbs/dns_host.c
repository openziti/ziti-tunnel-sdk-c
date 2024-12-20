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
#include <ziti/ziti.h>
#include <ziti/ziti_log.h>
#include "ziti_hosting.h"
#include "dns_host.h"

#ifndef PACKETSZ
# ifdef NS_PACKETSZ
#  define PACKETSZ NS_PACKETSZ
# else
#  define PACKETSZ 512
# endif // NS_PACKETSZ
#endif // PACKETSZ


typedef struct dns_host_conn_s {
    resolver_t resolver;
    allowed_hostnames_t allowed_domains;
} dns_host_conn_t;


typedef int (*rr_fmt)(const ns_msg *, const ns_rr*, dns_answer *ans, size_t max);
static int fmt_srv(const ns_msg *, const ns_rr*, dns_answer *ans, size_t max);
static int fmt_mx(const ns_msg *, const ns_rr*, dns_answer *ans, size_t max);
static int fmt_txt(const ns_msg *, const ns_rr*, dns_answer *ans, size_t max);

static model_map rr_formatters;

static uv_once_t init;
static void do_init() {
    model_map_setl(&rr_formatters, ns_t_srv, fmt_srv);
    model_map_setl(&rr_formatters, ns_t_mx, fmt_mx);
    model_map_setl(&rr_formatters, ns_t_txt, fmt_txt);
}

void dns_host_init() {
    uv_once(&init, do_init);
}

static void on_close(ziti_connection conn) {
    dns_host_conn_t *dns = ziti_conn_data(conn);
    if (dns) {
        res_nclose(&dns->resolver);
        while(!LIST_EMPTY(&dns->allowed_domains)) {
            struct allowed_hostname_s *ad = LIST_FIRST(&dns->allowed_domains);
            LIST_REMOVE(ad, _next);
            free(ad->domain_name);
            free(ad);
        }
        free(dns);
    }
}

static void on_conn_complete(ziti_connection conn, int status) {
    if (status != ZITI_OK) {
        ziti_close(conn, on_close);
    }
}

static void on_write(ziti_connection conn, ssize_t status, void *ctx) {
    if (ctx) free(ctx);
    
    if (status < 0) {
        ziti_close(conn, on_close);
    }
}

static bool is_allowed(const char *name, const dns_host_conn_t *dns) {
    struct allowed_hostname_s *ad;
    LIST_FOREACH(ad, &dns->allowed_domains, _next) {
        char *ptr = strstr(name, ad->domain_name);
        if (ptr != NULL && strcmp(ptr, ad->domain_name) == 0) { // ends with domain_name

            if (ptr == name) return true;

            if (*(ptr-1) == '.') // name is XXXX.$domain_name
                return true;
        }
    }
    return false;
}

#if _WIN32

void do_query(const dns_question *q, dns_message *resp, resolver_t *resolver) {
    DNS_RECORD *rrs = NULL;
    DNS_STATUS rc = DnsQuery_A(q->name, q->type, DNS_QUERY_STANDARD, NULL, &rrs, NULL);

    resp->status = rc;
    if (rc == DNS_RCODE_NOERROR) {
        int count = 0;
        DNS_RECORD *rr = rrs;
        while(rr != NULL) {
            count++;
            rr = rr->pNext;
        }

        resp->answer = calloc(count + 1, sizeof(dns_answer*));
        int idx = 0;
        for (rr = rrs; rr != NULL; rr = rr->pNext) {
            int type = rr->wType;
            rr_fmt fmt = model_map_getl(&rr_formatters, type);
            if (fmt) {
                dns_answer *a = alloc_dns_answer();
                a->type = type;
                a->ttl = (int)rr->dwTtl;
                a->data = malloc(PACKETSZ);
                fmt(NULL, rr, a, PACKETSZ);
                resp->answer[idx++] = a;
            }
        }
    }
}

static int fmt_srv(const ns_msg* msg, const ns_rr* rr, dns_answer *ans, size_t max) {
    ans->priority = rr->Data.SRV.wPriority;
    ans->weight = rr->Data.SRV.wWeight;
    ans->port = rr->Data.SRV.wPort;

    return snprintf(ans->data, max, "%s", rr->Data.SRV.pNameTarget);
}

static int fmt_mx(const ns_msg * msg, const ns_rr* rr, dns_answer *ans, size_t max) {
    ans->priority = rr->Data.MX.wPreference;
    return snprintf(ans->data, max, "%s", rr->Data.MX.pNameExchange);
}

static int fmt_txt(const ns_msg *msg, const ns_rr* rr, dns_answer *ans, size_t max) {
    return snprintf(ans->data, max, "%s", rr->Data.TXT.pStringArray[0]);
}

#else

static uint8_t *send_and_parse_query(const dns_question *q, int class, ns_msg *ans, resolver_t *resolver) {
    int buf_sz = PACKETSZ;
    uint8_t *resp_msg = NULL;
    int rc;

    for (int attempt = 0; attempt < 2; attempt++) { // retry the query with a larger buffer if first attempt was truncated
        resp_msg = calloc(buf_sz, sizeof(uint8_t));
        memset(ans, 0, sizeof(dns_question));
        rc = res_nquery(resolver, q->name, class, (int)q->type, resp_msg, buf_sz);
        if (rc < 0) {
            ZITI_LOG(DEBUG, "res_query for %s failed", q->name);
            break;
        }
        ns_initparse(resp_msg, rc, ans);
        bool trunc = ns_msg_getflag(*ans, ns_f_tc);
        if (!trunc) {
            break;
        } else {
            if (attempt == 0) {
                ZITI_LOG(DEBUG, "dns response truncated, repeating query with %d byte buffer", rc);
                free(resp_msg);
                resp_msg = NULL;
                buf_sz = rc; // try again with large enough buffer
            } else {
                rc = -1;
            }
        }
    }

    if (rc < 0) {
        free(resp_msg);
        resp_msg = NULL;
    }

    return resp_msg;
}

void do_query(const dns_question *q, dns_message *resp, resolver_t *resolver) {
    ns_msg ans = {0};
    uint8_t *resp_msg = send_and_parse_query(q, ns_c_in, &ans, resolver);
    if (resp_msg == NULL) {
        resp->status = ns_r_servfail;
        return;
    } else {
        resp->status = ns_msg_getflag(ans, ns_f_rcode);
        int rr_count = ns_msg_count(ans, ns_s_an);
        if (rr_count > 0) {
            ns_rr rr;
            rr_fmt fmt;
            int a_idx = 0;
            resp->answer = calloc(rr_count + 1, sizeof(dns_answer *));
            for (int i = 0; i < rr_count; i++) {
                if (ns_parserr(&ans, ns_s_an, i, &rr) == 0 &&
                    (fmt = model_map_getl(&rr_formatters, ns_rr_type(rr))) != 0) {
                    dns_answer *a = alloc_dns_answer();
                    a->ttl = ns_rr_ttl(rr);
                    a->type = ns_rr_type(rr);
                    a->data = malloc(PACKETSZ);
                    fmt(&ans, &rr, a, PACKETSZ);
                    resp->answer[a_idx++] = a;
                }
            }
        }
        free(resp_msg);
    }
}

static int fmt_srv(const ns_msg* msg, const ns_rr* rr, dns_answer *ans, size_t max) {
    uint16_t *ptr = (uint16_t *) ns_rr_rdata(*rr);
    ans->priority = ntohs(*ptr);
    ans->weight = ntohs(*(ptr + 1));
    ans->port = ntohs(*(ptr + 2));

    return ns_name_uncompress(ns_msg_base(*msg), ns_msg_end(*msg), (uint8_t *)(ptr + 3), (char*)ans->data, max);
}

static int fmt_mx(const ns_msg * msg, const ns_rr* rr, dns_answer *ans, size_t max) {
    uint16_t *ptr = (uint16_t *) ns_rr_rdata(*rr);
    ans->priority = ntohs(*ptr);
    return ns_name_uncompress(ns_msg_base(*msg), ns_msg_end(*msg), (uint8_t *)(ptr + 1), (char*)ans->data, max);
}

static int fmt_txt(const ns_msg *msg, const ns_rr* rr, dns_answer *ans, size_t max) {
    const uint8_t *ptr = ns_rr_rdata(*rr);
    unsigned int len = ns_rr_rdlen(*rr);
    if (len > max) {
        len = (unsigned int)max;
    }
    len--;
    memcpy((char*)ans->data, ptr+1, len);
    ((char*)ans->data)[len] = 0;
    return (int)len;
}

#endif

static ssize_t on_dns_req(ziti_connection conn, const uint8_t *data, ssize_t datalen) {
    if (datalen < 0) {
        ziti_close(conn, on_close);
        return 0;
    }
    dns_host_conn_t *dns = ziti_conn_data(conn);

    ZITI_LOG(DEBUG, "resolve_req: %.*s", (int)datalen, data);
    dns_message msg = {0};
    parse_dns_message(&msg, (const char*) data, datalen);
    dns_question *q = msg.question[0];

    if (is_allowed(q->name, dns)) {
        do_query(q, &msg, &dns->resolver);
    } else {
        msg.status = ns_r_refused;
    }

    size_t msg_len = 0;
    char *json = dns_message_to_json(&msg, 0, &msg_len);
    ziti_write(conn, (uint8_t *)json, msg_len, on_write, json);
    free_dns_message(&msg);
    return datalen;
}

void accept_resolver_conn(ziti_connection conn, allowed_hostnames_t *allowed) {
    uv_once(&init, do_init);
    dns_host_conn_t *dns = calloc(1, sizeof(dns_host_conn_t));
    if (res_ninit(&dns->resolver) == 0) {
        ziti_conn_set_data(conn, dns);
        struct allowed_hostname_s *ah;
        LIST_FOREACH(ah, allowed, _next) {
            if (ah->domain_name[0] == '*' && ah->domain_name[1] == '.') {
                struct allowed_hostname_s *allowed_domain = calloc(1, sizeof(struct allowed_hostname_s));
                allowed_domain->domain_name = strdup(ah->domain_name + 2); // skip *.
                LIST_INSERT_HEAD(&dns->allowed_domains, allowed_domain, _next);
            }
        }
        ziti_accept(conn, on_conn_complete, on_dns_req);
    } else {
        ziti_close(conn, on_close);
    }
}



IMPL_MODEL(dns_question, DNS_Q_MODEL)
IMPL_MODEL(dns_answer, DNS_A_MODEL)
IMPL_MODEL(dns_message, DNS_MSG_MODEL)