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
#include <string>
#include "../ziti_hosting.h"

static ziti_listen_options make_listen_opts(const char *identity, ziti_listen_identity_type identity_type,
                                            bool bind_with_identity = false) {
    ziti_listen_options opts{};
    opts.identity = const_cast<char *>(identity);
    opts.listen_identity_type = identity_type;
    opts.bind_with_identity = bind_with_identity;
    return opts;
}

// returns the resolved identity, or "<as-is>" when the configured options should be used unchanged
static std::string resolve(const ziti_listen_options *opts, const char *tunneler_id_name, int expected_rc = 0) {
    char *resolved = nullptr;
    REQUIRE(resolve_listen_identity(opts, tunneler_id_name, &resolved) == expected_rc);
    std::string result = resolved != nullptr ? resolved : "<as-is>";
    free(resolved);
    return result;
}

TEST_CASE("resolve_listen_identity preserves case without listenIdentityType", "[hosting]") {
    SECTION("bare placeholder") {
        auto opts = make_listen_opts("$tunneler_id.name", ziti_listen_identity_type_Unknown);
        CHECK(resolve(&opts, "MyRouter-01") == "MyRouter-01");
    }

    SECTION("placeholder embedded in a larger template") {
        auto opts = make_listen_opts("svc-$tunneler_id.name", ziti_listen_identity_type_Unknown);
        CHECK(resolve(&opts, "MyRouter-01") == "svc-MyRouter-01");
    }

    SECTION("placeholder used more than once") {
        auto opts = make_listen_opts("$tunneler_id.name-$tunneler_id.name", ziti_listen_identity_type_Unknown);
        CHECK(resolve(&opts, "MyRouter-01") == "MyRouter-01-MyRouter-01");
    }

    SECTION("literal identity is used as-is") {
        auto opts = make_listen_opts("MyLiteralIdentity", ziti_listen_identity_type_Unknown);
        CHECK(resolve(&opts, "MyRouter-01") == "<as-is>");
    }

    SECTION("bindUsingEdgeIdentity is left to the sdk") {
        auto opts = make_listen_opts(nullptr, ziti_listen_identity_type_Unknown, true);
        CHECK(resolve(&opts, "MyRouter-01") == "<as-is>");
    }
}

TEST_CASE("resolve_listen_identity lower-cases with listenIdentityType=dns", "[hosting]") {
    SECTION("bare placeholder") {
        auto opts = make_listen_opts("$tunneler_id.name", ziti_listen_identity_type_dns);
        CHECK(resolve(&opts, "MyRouter-01") == "myrouter-01");
    }

    SECTION("placeholder embedded in a larger template") {
        auto opts = make_listen_opts("Svc-$tunneler_id.name", ziti_listen_identity_type_dns);
        CHECK(resolve(&opts, "MyRouter-01") == "svc-myrouter-01");
    }

    SECTION("literal identity") {
        auto opts = make_listen_opts("MyLiteralIdentity", ziti_listen_identity_type_dns);
        CHECK(resolve(&opts, "MyRouter-01") == "myliteralidentity");
    }

    SECTION("bindUsingEdgeIdentity") {
        auto opts = make_listen_opts(nullptr, ziti_listen_identity_type_dns, true);
        CHECK(resolve(&opts, "MyRouter-01") == "myrouter-01");
    }
}

TEST_CASE("resolve_listen_identity does not truncate long identities", "[hosting]") {
    std::string long_name(300, 'N');

    SECTION("long literal identity is used as-is") {
        std::string literal(300, 'L');
        auto opts = make_listen_opts(literal.c_str(), ziti_listen_identity_type_Unknown);
        CHECK(resolve(&opts, "MyRouter-01") == "<as-is>");
    }

    SECTION("long literal identity with dns") {
        std::string literal(300, 'L');
        auto opts = make_listen_opts(literal.c_str(), ziti_listen_identity_type_dns);
        CHECK(resolve(&opts, "MyRouter-01") == std::string(300, 'l'));
    }

    SECTION("long tunneler name in a template") {
        auto opts = make_listen_opts("svc-$tunneler_id.name", ziti_listen_identity_type_Unknown);
        CHECK(resolve(&opts, long_name.c_str()) == "svc-" + long_name);
    }

    SECTION("long tunneler name with bindUsingEdgeIdentity and dns") {
        auto opts = make_listen_opts(nullptr, ziti_listen_identity_type_dns, true);
        CHECK(resolve(&opts, long_name.c_str()) == std::string(300, 'n'));
    }
}

TEST_CASE("resolve_listen_identity handles empty/null inputs", "[hosting]") {
    SECTION("null listen options") {
        CHECK(resolve(nullptr, "MyRouter-01") == "<as-is>");
    }

    SECTION("no identity configured") {
        auto opts = make_listen_opts(nullptr, ziti_listen_identity_type_dns);
        CHECK(resolve(&opts, "MyRouter-01") == "<as-is>");
    }

    SECTION("empty identity") {
        auto opts = make_listen_opts("", ziti_listen_identity_type_dns);
        CHECK(resolve(&opts, "MyRouter-01") == "<as-is>");
    }

    SECTION("unknown tunneler name fails when the placeholder is used") {
        auto opts = make_listen_opts("svc-$tunneler_id.name", ziti_listen_identity_type_Unknown);
        resolve(&opts, nullptr, -1);
        resolve(&opts, "", -1);
    }

    SECTION("unknown tunneler name fails with bindUsingEdgeIdentity and dns") {
        auto opts = make_listen_opts(nullptr, ziti_listen_identity_type_dns, true);
        resolve(&opts, nullptr, -1);
    }

    SECTION("unknown tunneler name is not needed for a literal identity") {
        auto opts = make_listen_opts("MyLiteralIdentity", ziti_listen_identity_type_dns);
        CHECK(resolve(&opts, nullptr) == "myliteralidentity");
    }
}
