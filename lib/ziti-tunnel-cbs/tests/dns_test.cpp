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
    CHECK_THAT(msg.answer[0]->data, Catch::Contains("993 imap.gmail.com"));

    size_t jsonlen;
    auto json = dns_message_to_json(&msg, 0, &jsonlen);
    printf("%.*s\n\n", (int)jsonlen, json);

    res_nclose(&resolver);
    free(json);
    free_dns_message(&msg);
}
