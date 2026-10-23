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
#include "ziti/ziti_tunnel_cbs.h"

static std::string replace_all(const char *source, const char *substring, const char *with) {
    char *replaced = string_replace_all(source, substring, with);
    REQUIRE(replaced != nullptr);
    std::string result = replaced;
    free(replaced);
    return result;
}

TEST_CASE("string_replace_all", "[string]") {
    SECTION("no occurrences") {
        CHECK(replace_all("my-service", "$dst_ip", "10.0.0.1") == "my-service");
    }

    SECTION("single occurrence") {
        CHECK(replace_all("host-$dst_ip", "$dst_ip", "10.0.0.1") == "host-10.0.0.1");
    }

    SECTION("multiple occurrences") {
        CHECK(replace_all("$dst_ip-$dst_ip.$dst_ip", "$dst_ip", "x") == "x-x.x");
    }

    SECTION("replacement longer than substring") {
        std::string with(300, 'w');
        CHECK(replace_all("a$v-$vb", "$v", with.c_str()) == "a" + with + "-" + with + "b");
    }

    SECTION("replacement shorter than substring") {
        CHECK(replace_all("$tunneler_id.name/$tunneler_id.name", "$tunneler_id.name", "r") == "r/r");
    }

    SECTION("empty replacement") {
        CHECK(replace_all("a$vb$v", "$v", "") == "ab");
    }

    SECTION("replacement contains the substring") {
        CHECK(replace_all("$v.$v", "$v", "$v$v") == "$v$v.$v$v");
    }

    SECTION("long source") {
        std::string source = std::string(200, 's') + "$dst_hostname" + std::string(200, 's');
        CHECK(replace_all(source.c_str(), "$dst_hostname", "example.com") ==
              std::string(200, 's') + "example.com" + std::string(200, 's'));
    }

    SECTION("empty substring") {
        CHECK(replace_all("unchanged", "", "x") == "unchanged");
    }
}
