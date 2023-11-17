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

#include "dns_host.h"
#include <stdint.h>

static int parse_dns_q(dns_question *q, const unsigned char *buf, size_t buflen) {
    const uint8_t *p = buf;
    size_t namelen = 0;

    while(*p != 0) {
        namelen += (*p + 1);
        p += (*p + 1);
    }
    p++;
    int type = ntohs(*(uint16_t*)p);
    int cls = ntohs(*(((uint16_t*)p) + 1));
    if (cls != 1) {
        return -1;
    }

    q->type = type;
    q->name = malloc(namelen+1);
    char *wp = q->name;
    p = buf;
    while(*p != 0) {
        if (wp != q->name) *wp++ = '.';

        memcpy(wp, p + 1, *p);
        wp += *p;
        p += (*p + 1);
    }
    *wp = 0;

    return (int)(p - buf);
}

int parse_dns_req(dns_message *msg, const unsigned char* buf, size_t buflen) {

    msg->id = ntohs(*((uint16_t*)buf));
    dns_flags_t flags;
    flags.raw = ntohs(*((uint16_t*)buf + 1));

    if (flags.is_response) return -1;

    int qcount = ntohs(*((uint16_t*)buf + 2));
    if (qcount != 1) return -1;

    msg->recursive = flags.rd;
    msg->question = calloc(2, sizeof(dns_question*));
    msg->question[0] = calloc(1, sizeof(dns_question));
    parse_dns_q(msg->question[0], buf + 12, buflen - 12);


    return 0;
}
