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

#include "catch2/catch.hpp"
#include "../dns_host.h"

TEST_CASE("resolve", "[dns]") {
    dns_host_init();

    resolver_t resolver;
    res_ninit(&resolver);

    dns_message msg = {0};

    dns_question q;
    q.type = 15;
    q.name = strdup("yahoo.com");

    do_query(&q, &msg, &resolver);

    size_t jsonlen;
    auto json = dns_message_to_json(&msg, 0, &jsonlen);
    printf("%.*s\n\n", (int)jsonlen, json);

    res_nclose(&resolver);
    free(json);
    free_dns_message(&msg);
}


TEST_CASE("resolveSRV", "[dns]") {
    dns_host_init();

    resolver_t resolver;
    res_ninit(&resolver);

    dns_message msg = {0};

    dns_question q;
    q.type = 33;
    q.name = strdup("_imaps._tcp.gmail.com");

    do_query(&q, &msg, &resolver);

    CHECK(msg.status == 0);
    REQUIRE(msg.answer != nullptr);
    CHECK(msg.answer[0]->type == 33);
    CHECK(msg.answer[0]->port == 993);
    CHECK_THAT(msg.answer[0]->data, Catch::Contains("imap.gmail.com"));

    size_t jsonlen;
    auto json = dns_message_to_json(&msg, 0, &jsonlen);
    printf("%.*s\n\n", (int)jsonlen, json);

    res_nclose(&resolver);
    free(json);
    free_dns_message(&msg);
}

TEST_CASE("dns wire parse", "[dns]") {
    unsigned char b[] = {
  0x53, 0x6b, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x01, 0x05, 0x79, 0x61, 0x68,
  0x6f, 0x6f, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00,
  0x01, 0x00, 0x01, 0x00, 0x00, 0x29, 0x10, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0a,
  0x00, 0x08, 0x28, 0x27, 0x1d, 0x17, 0x27, 0x50,
  0xa0, 0x4e
};

    dns_message req = {0};
    CHECK(parse_dns_req(&req, b, sizeof(b)) == 0);

    CHECK(req.answer == nullptr);

    CHECK(req.question != nullptr);
    CHECK(req.question[0] != nullptr);
    CHECK(req.question[1] == nullptr);

    CHECK(req.question[0]->type == 1);
    CHECK_THAT(req.question[0]->name, Catch::Matches("yahoo.com"));

    free_dns_message(&req);
}

TEST_CASE("dns parse MX", "[dns]") {
    uint8_t b[] = {
  0xbd, 0x2d, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x01, 0x05, 0x79, 0x61, 0x68,
  0x6f, 0x6f, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00,
  0x0f, 0x00, 0x01, 0x00, 0x00, 0x29, 0x02, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

    dns_message req = {0};
    CHECK(parse_dns_req(&req, b, sizeof(b)) == 0);

    CHECK(req.answer == nullptr);

    CHECK(req.question != nullptr);
    CHECK(req.question[0] != nullptr);
    CHECK(req.question[1] == nullptr);

    CHECK(req.question[0]->type == 15);
    CHECK_THAT(req.question[0]->name, Catch::Matches("yahoo.com"));

    free_dns_message(&req);

}
