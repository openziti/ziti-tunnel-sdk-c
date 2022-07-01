/*
 Copyright 2021-2022 NetFoundry Inc.

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
#include "ziti/ziti_tunnel.h"
#include "ziti_tunnel_priv.h"

/** make valid json from a plain string and parse it as a ziti_address */
#define ZA_INIT_STR(za, s) (( parse_ziti_address((za), "\"" s "\"", strlen("\"" s "\"")) ), (za))

TEST_CASE("address_match", "[address]") {
#if 0
    CHECK(msg.status == 0);
    REQUIRE(msg.answer != nullptr);
    CHECK(msg.answer[0]->type == 33);
    CHECK(msg.answer[0]->port == 993);
    CHECK_THAT(msg.answer[0]->data, Catch::Contains("imap.gmail.com"));
#endif
    struct tunneler_ctx_s tctx = { };
    ziti_address za;
    ip_addr_t ip;
    LIST_INIT(&tctx.intercepts);

    intercept_ctx_t *intercept_s1 = intercept_ctx_new(&tctx, "s1", nullptr);
    LIST_INSERT_HEAD(&tctx.intercepts, intercept_s1, entries);
    intercept_ctx_add_address(intercept_s1, ZA_INIT_STR(&za, "192.168.0.88"));
    intercept_ctx_add_protocol(intercept_s1, "tcp");
    intercept_ctx_add_port_range(intercept_s1, 80, 80);

    IP_ADDR4(&ip, 127, 0, 0, 1);
    REQUIRE(lookup_intercept_by_address(&tctx, "tcp", &ip, 80) == nullptr);

    IP_ADDR4(&ip, 192, 168, 0, 88);
    REQUIRE(lookup_intercept_by_address(&tctx, "tcp", &ip, 80) == intercept_s1);

    intercept_ctx_t *intercept_s2 = intercept_ctx_new(&tctx, "s2", nullptr);
    LIST_INSERT_HEAD(&tctx.intercepts, intercept_s2, entries);
    intercept_ctx_add_address(intercept_s2, ZA_INIT_STR(&za, "192.168.0.0/24"));
    intercept_ctx_add_protocol(intercept_s2, "tcp");
    intercept_ctx_add_port_range(intercept_s2, 80, 80);

    // s2 should be overlooked even though it matches and precedes s1 in the intercept list
    REQUIRE(lookup_intercept_by_address(&tctx, "tcp", &ip, 80) == intercept_s1);

    // s2 should match CIDR address
    IP_ADDR4(&ip, 192, 168, 0, 10);
    REQUIRE(lookup_intercept_by_address(&tctx, "tcp", &ip, 80) == intercept_s2);

    intercept_ctx_t *intercept_s3 = intercept_ctx_new(&tctx, "s3", nullptr);
    LIST_INSERT_HEAD(&tctx.intercepts, intercept_s3, entries);
    intercept_ctx_add_address(intercept_s3, ZA_INIT_STR(&za, "192.168.0.0/16"));
    intercept_ctx_add_protocol(intercept_s3, "tcp");
    intercept_ctx_add_port_range(intercept_s3, 80, 85);

    // s2 should still win due to smaller cidr range
    IP_ADDR4(&ip, 192, 168, 0, 10);
    REQUIRE(lookup_intercept_by_address(&tctx, "tcp", &ip, 80) == intercept_s2);

    intercept_ctx_t *intercept_s4 = intercept_ctx_new(&tctx, "s4", nullptr);
    LIST_INSERT_HEAD(&tctx.intercepts, intercept_s4, entries);
    intercept_ctx_add_address(intercept_s4, ZA_INIT_STR(&za, "192.168.0.0/16"));
    intercept_ctx_add_protocol(intercept_s4, "tcp");
    intercept_ctx_add_port_range(intercept_s4, 80, 90);

    // s2 should be overlooked despite CIDR match with smaller prefix due to port mismatch
    // s3 should win over s4 due to smaller port range
    IP_ADDR4(&ip, 192, 168, 0, 10);
    REQUIRE(lookup_intercept_by_address(&tctx, "tcp", &ip, 81) == intercept_s3);

    intercept_ctx_add_address(intercept_s1, ZA_INIT_STR(&za, "*.ziti"));

}