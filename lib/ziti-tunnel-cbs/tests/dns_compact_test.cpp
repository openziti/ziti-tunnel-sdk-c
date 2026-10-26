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
#include <chrono>
#include <cstring>
#include <string>
#include <vector>
#include <ziti/ziti_dns.h>

using names = std::vector<std::string>;

// NULL-terminated list of strdup'ed names, as ziti_dns_get_domains() returns it
static char **make_list(const names &in) {
    char **list = (char **) calloc(in.size() + 1, sizeof(char *));
    for (size_t i = 0; i < in.size(); i++) {
        list[i] = strdup(in[i].c_str());
    }
    return list;
}

static names take_list(char **list) {
    names out;
    for (char **d = list; *d != nullptr; d++) {
        out.emplace_back(*d);
        free(*d);
    }
    free(list);
    return out;
}

static names compact(const names &in, size_t limit, const std::vector<const char *> &reserved = {}) {
    std::vector<const char *> r(reserved);
    r.push_back(nullptr);
    char **list = make_list(in);
    size_t n = ziti_dns_compact_domains(list, limit, r.data());
    names out = take_list(list);
    CHECK(n == out.size());
    return out;
}

TEST_CASE("compact: lists within the limit are not changed", "[dns][compact]") {
    char **list = make_list({"b.example.com", "a.example.com"});
    char *first = list[0];
    CHECK(ziti_dns_compact_domains(list, 2, nullptr) == 2);
    CHECK(list[0] == first);  // not even sorted or copied
    CHECK(take_list(list) == names{"b.example.com", "a.example.com"});
}

TEST_CASE("compact: names below another name are dropped first", "[dns][compact]") {
    // a routing domain covers its subdomains, so this captures no additional names
    CHECK(compact({"a.b.example", "b.example", "x.y.example", "deep.a.b.example"}, 2) == names{"b.example", "x.y.example"});
}

TEST_CASE("compact: the largest groups of the deepest parents are merged first", "[dns][compact]") {
    names in = {"a.p.corp.example", "b.p.corp.example", "c.p.corp.example",
                "a.q.corp.example", "b.q.corp.example",
                "other.test"};
    // merging p (3 -> 1) is enough; q is left alone, nothing is merged into corp.example
    CHECK(compact(in, 4) == names{"a.q.corp.example", "b.q.corp.example", "other.test", "p.corp.example"});
    // merging p and q is enough at the same depth
    CHECK(compact(in, 3) == names{"other.test", "p.corp.example", "q.corp.example"});
    // only then the next level up
    CHECK(compact(in, 2) == names{"corp.example", "other.test"});
}

TEST_CASE("compact: merging climbs levels until the list fits", "[dns][compact]") {
    names in = {"a.x.p.example.com", "b.y.p.example.com", "c.z.q.example.com", "d.w.q.example.com"};
    CHECK(compact(in, 1) == names{"example.com"});
}

TEST_CASE("compact: names are never merged into a parent with fewer than two labels", "[dns][compact]") {
    names in = {"a.test", "b.test", "c.test", "single"};
    char **list = make_list(in);
    CHECK(ziti_dns_compact_domains(list, 1, nullptr) == 4);
    CHECK(take_list(list) == names{"a.test", "b.test", "c.test", "single"});
}

TEST_CASE("compact: reserved domains are not taken over", "[dns][compact]") {
    names in = {"a.p.corp.example", "b.p.corp.example", "c.p.corp.example", "x.other.test", "y.other.test"};

    SECTION("not into a reserved domain") {
        // corp.example is routed by another link: merging p into corp.example would tie with it,
        // and p.corp.example is below it, so it would take over that link's names
        CHECK(compact(in, 2, {"corp.example"}) ==
              names{"a.p.corp.example", "b.p.corp.example", "c.p.corp.example", "other.test"});
    }

    SECTION("into a parent above a reserved domain") {
        // the other link keeps vpn.corp.example, its routing domain is longer
        CHECK(compact(in, 2, {"vpn.corp.example"}) == names{"other.test", "p.corp.example"});
    }

    SECTION("the root domain is not a reservation") {
        CHECK(compact(in, 2, {".", ""}) == names{"other.test", "p.corp.example"});
    }
}

TEST_CASE("compact: the result is sorted and without duplicates", "[dns][compact]") {
    names out = compact({"z.b.test", "y.b.test", "a.c.test", "b.c.test", "m.test"}, 3);
    CHECK(out == names{"b.test", "c.test", "m.test"});
}

TEST_CASE("compact: large lists are compacted quickly", "[dns][compact]") {
    // 100000 hostnames in 2000 environments of 50 hosts each, in 20 domains
    names in;
    for (int d = 0; d < 20; d++) {
        for (int e = 0; e < 100; e++) {
            for (int h = 0; h < 50; h++) {
                in.push_back("host" + std::to_string(h) + ".env" + std::to_string(e) + ".domain" + std::to_string(d) + ".example");
            }
        }
    }

    auto start = std::chrono::steady_clock::now();
    names out = compact(in, 1024);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
    printf("compacted %zu names to %zu in %lld ms\n", in.size(), out.size(), (long long) ms);

    // merging all 2000 environments is not enough, so 10 of the domains (100 environments each) are merged too
    CHECK(out.size() == 1010);
    CHECK(ms < 10000);  // only catches pathological slowness; debug builds take about 50ms
    for (const auto &n : out) {
        CHECK(n.find("domain") != std::string::npos);  // never merged above domainN.example
    }
}
