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

static ziti_listen_options make_listen_opts(const char *identity, ziti_listen_identity_type identity_type,
                                            bool bind_with_identity = false) {
    ziti_listen_options opts{};
    opts.identity = const_cast<char *>(identity);
    opts.listen_identity_type = identity_type;
    opts.bind_with_identity = bind_with_identity;
    return opts;
}

TEST_CASE("resolve_listen_identity preserves case without listenIdentityType", "[hosting]") {
    char buf[128];

    SECTION("bare placeholder") {
        auto opts = make_listen_opts("$tunneler_id.name", ziti_listen_identity_type_Unknown);
        CHECK_THAT(resolve_listen_identity(buf, sizeof(buf), &opts, "MyRouter-01"), Catch::Equals("MyRouter-01"));
    }

    SECTION("placeholder embedded in a larger template") {
        auto opts = make_listen_opts("svc-$tunneler_id.name", ziti_listen_identity_type_Unknown);
        CHECK_THAT(resolve_listen_identity(buf, sizeof(buf), &opts, "MyRouter-01"), Catch::Equals("svc-MyRouter-01"));
    }

    SECTION("literal identity") {
        auto opts = make_listen_opts("MyLiteralIdentity", ziti_listen_identity_type_Unknown);
        CHECK_THAT(resolve_listen_identity(buf, sizeof(buf), &opts, "MyRouter-01"), Catch::Equals("MyLiteralIdentity"));
    }

    SECTION("bindUsingEdgeIdentity") {
        auto opts = make_listen_opts(nullptr, ziti_listen_identity_type_Unknown, true);
        CHECK_THAT(resolve_listen_identity(buf, sizeof(buf), &opts, "MyRouter-01"), Catch::Equals("MyRouter-01"));
    }
}

TEST_CASE("resolve_listen_identity lower-cases with listenIdentityType=dns", "[hosting]") {
    char buf[128];

    SECTION("bare placeholder") {
        auto opts = make_listen_opts("$tunneler_id.name", ziti_listen_identity_type_dns);
        CHECK_THAT(resolve_listen_identity(buf, sizeof(buf), &opts, "MyRouter-01"), Catch::Equals("myrouter-01"));
    }

    SECTION("placeholder embedded in a larger template") {
        auto opts = make_listen_opts("Svc-$tunneler_id.name", ziti_listen_identity_type_dns);
        CHECK_THAT(resolve_listen_identity(buf, sizeof(buf), &opts, "MyRouter-01"), Catch::Equals("svc-myrouter-01"));
    }

    SECTION("literal identity") {
        auto opts = make_listen_opts("MyLiteralIdentity", ziti_listen_identity_type_dns);
        CHECK_THAT(resolve_listen_identity(buf, sizeof(buf), &opts, "MyRouter-01"), Catch::Equals("myliteralidentity"));
    }

    SECTION("bindUsingEdgeIdentity") {
        auto opts = make_listen_opts(nullptr, ziti_listen_identity_type_dns, true);
        CHECK_THAT(resolve_listen_identity(buf, sizeof(buf), &opts, "MyRouter-01"), Catch::Equals("myrouter-01"));
    }
}

TEST_CASE("resolve_listen_identity handles empty/null inputs", "[hosting]") {
    char buf[128];

    SECTION("null listen options") {
        CHECK(resolve_listen_identity(buf, sizeof(buf), nullptr, "MyRouter-01") == nullptr);
    }

    SECTION("no identity configured") {
        auto opts = make_listen_opts(nullptr, ziti_listen_identity_type_dns);
        CHECK(resolve_listen_identity(buf, sizeof(buf), &opts, "MyRouter-01") == nullptr);
    }

    SECTION("empty identity") {
        auto opts = make_listen_opts("", ziti_listen_identity_type_dns);
        CHECK(resolve_listen_identity(buf, sizeof(buf), &opts, "MyRouter-01") == nullptr);
    }

    SECTION("null tunneler_id_name substitutes empty string") {
        auto opts = make_listen_opts("svc-$tunneler_id.name", ziti_listen_identity_type_Unknown);
        CHECK_THAT(resolve_listen_identity(buf, sizeof(buf), &opts, nullptr), Catch::Equals("svc-"));
    }
}
