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
#include <vector>
#include <ziti/ziti_dns.h>

static int domains_changed_count = 0;

static void count_domains_changed(netif_handle, uv_loop_t *) {
    domains_changed_count++;
}

static int refresh_fallback_count = 0;

static void count_refresh_fallback(netif_handle, uv_loop_t *) {
    refresh_fallback_count++;
}

static int ignore_route(netif_handle, const char *) {
    return 0;
}

static std::vector<std::string> get_domains() {
    std::vector<std::string> result;
    char **domains = ziti_dns_get_domains();
    REQUIRE(domains != nullptr);
    for (char **d = domains; *d != nullptr; d++) {
        result.emplace_back(*d);
        free(*d);
    }
    free(domains);
    return result;
}

// ziti_dns keeps the tunneler (and through it the driver) after a test returns, so the driver must outlive the test.
// the DNS range matches other tests, so reserved addresses in the shared IP pool stay the same
static tunneler_context setup_dns() {
    static netif_driver_t driver{};
    driver.add_route = ignore_route;
    driver.delete_route = ignore_route;
    driver.dns_domains_changed = count_domains_changed;
    driver.dns_refresh_fallback = count_refresh_fallback;

    tunneler_sdk_options opts{};
    opts.l3_netif_driver = &driver;
    tunneler_context tnlr = ziti_tunneler_init_host_only(&opts, uv_default_loop());
    REQUIRE(tnlr != nullptr);
    REQUIRE(ziti_dns_setup(tnlr, "100.64.0.2", "100.64.0.1/24") == 0);
    return tnlr;
}

static void register_name(const char *name, void *intercept) {
    ziti_address addr;
    REQUIRE(ziti_address_from_string(&addr, name));
    ziti_dns_register_hostname(&addr, intercept);
}

// ziti_dns keeps global state, so all scenarios run in sequence within a single test case
TEST_CASE("intercepted names are reported to the netif driver", "[dns]") {
    setup_dns();

    CHECK(get_domains().empty());
    CHECK_FALSE(ziti_dns_has_upstream());

    int svc_a, svc_b, svc_c;

    // hostnames are normalized, wildcard domains lose their "*." prefix, and the list is sorted
    domains_changed_count = 0;
    register_name("App.Example.COM", &svc_a);
    register_name("*.svc.example.org", &svc_b);
    register_name("db.example.test.", &svc_c);
    CHECK(domains_changed_count == 3);
    CHECK(get_domains() == std::vector<std::string>{"app.example.com", "db.example.test", "svc.example.org"});

    // CIDR intercepts do not need DNS
    domains_changed_count = 0;
    register_name("10.0.0.0/8", &svc_c);
    CHECK(domains_changed_count == 0);

    // a name that is intercepted by several services is reported once
    register_name("app.example.com", &svc_b);
    CHECK(get_domains() == std::vector<std::string>{"app.example.com", "db.example.test", "svc.example.org"});

    // a name remains while any service still intercepts it
    domains_changed_count = 0;
    ziti_dns_deregister_intercept(&svc_a);
    CHECK(domains_changed_count == 1);
    CHECK(get_domains() == std::vector<std::string>{"app.example.com", "db.example.test", "svc.example.org"});

    ziti_dns_deregister_intercept(&svc_b);
    CHECK(get_domains() == std::vector<std::string>{"db.example.test"});

    ziti_dns_deregister_intercept(&svc_c);
    CHECK(get_domains().empty());
}

TEST_CASE("fallback upstream does not count as a configured upstream", "[dns]") {
    tunneler_context tnlr = setup_dns();

    // a stale fallback refresh request reaches the driver
    refresh_fallback_count = 0;
    ziti_tunneler_dns_refresh_fallback(tnlr);
    CHECK(refresh_fallback_count == 1);

    // no fallback servers: nothing to forward to
    CHECK(ziti_dns_set_fallback_upstream(uv_default_loop(), nullptr, 0, 0) == 0);
    CHECK_FALSE(ziti_dns_has_upstream());

    struct sockaddr_storage addrs[2]{};
    REQUIRE(uv_ip4_addr("192.0.2.53", 53, (struct sockaddr_in *) &addrs[0]) == 0);
    REQUIRE(uv_ip6_addr("2001:db8::53", 53, (struct sockaddr_in6 *) &addrs[1]) == 0);

    CHECK(ziti_dns_set_fallback_upstream(uv_default_loop(), addrs, 2, 0) == 0);
    CHECK_FALSE(ziti_dns_has_upstream());

    tunnel_upstream_dns upstream{};
    upstream.host = const_cast<char *>("192.0.2.1");
    tunnel_upstream_dns *upstreams[] = {&upstream, nullptr};
    domains_changed_count = 0;
    REQUIRE(ziti_dns_set_upstream(uv_default_loop(), upstreams) == 0);
    CHECK(ziti_dns_has_upstream());
    // the driver decides on the default route from upstream availability
    CHECK(domains_changed_count == 1);

    tunnel_upstream_dns *none[] = {nullptr};
    REQUIRE(ziti_dns_set_upstream(uv_default_loop(), none) == 0);
    CHECK_FALSE(ziti_dns_has_upstream());
}
