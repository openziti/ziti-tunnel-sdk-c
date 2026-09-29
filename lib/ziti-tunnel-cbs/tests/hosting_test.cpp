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
#include "../ziti_hosting.h"

TEST_CASE("resolve_listen_identity normalizes tunneler_id.name to lower-case", "[hosting]") {
    char buf[128];

    SECTION("bare placeholder") {
        char *resolved = resolve_listen_identity(buf, sizeof(buf), "$tunneler_id.name", "MyRouter-01");
        REQUIRE(resolved != nullptr);
        CHECK_THAT(resolved, Catch::Equals("myrouter-01"));
    }

    SECTION("placeholder embedded in a larger template") {
        char *resolved = resolve_listen_identity(buf, sizeof(buf), "svc-$tunneler_id.name", "MyRouter-01");
        REQUIRE(resolved != nullptr);
        CHECK_THAT(resolved, Catch::Equals("svc-myrouter-01"));
    }

    SECTION("already lower-case identity name is unaffected") {
        char *resolved = resolve_listen_identity(buf, sizeof(buf), "$tunneler_id.name", "myrouter-01");
        REQUIRE(resolved != nullptr);
        CHECK_THAT(resolved, Catch::Equals("myrouter-01"));
    }
}

TEST_CASE("resolve_listen_identity leaves literal (non-templated) identity untouched", "[hosting]") {
    char buf[128];

    char *resolved = resolve_listen_identity(buf, sizeof(buf), "MyLiteralIdentity", "MyRouter-01");
    CHECK(resolved == nullptr);
}

TEST_CASE("resolve_listen_identity handles empty/null inputs", "[hosting]") {
    char buf[128];

    SECTION("null identity_template") {
        CHECK(resolve_listen_identity(buf, sizeof(buf), nullptr, "MyRouter-01") == nullptr);
    }

    SECTION("empty identity_template") {
        CHECK(resolve_listen_identity(buf, sizeof(buf), "", "MyRouter-01") == nullptr);
    }

    SECTION("null tunneler_id_name substitutes empty string") {
        char *resolved = resolve_listen_identity(buf, sizeof(buf), "svc-$tunneler_id.name", nullptr);
        REQUIRE(resolved != nullptr);
        CHECK_THAT(resolved, Catch::Equals("svc-"));
    }
}
