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

#include <functional>
#include "catch2/catch.hpp"
#include "ziti/ziti_tunnel.h"
#include "ziti/ziti_tunnel_cbs.h"
#include "ziti/ziti_dns.h"
#include "ziti/model_collections.h"

#include <set>
#include <string>

static int mock_add_route(netif_handle tun, const char *dest) {
    return 0;
}

static int mock_delete_route(netif_handle tun, const char *dest) {
    return 0;
}

static void ziti_address_from_index(ziti_address *za, uint32_t i) {
    static char json[32];
    snprintf(json, sizeof(json), "\"host%03d.\"", i);
    parse_ziti_address(za, json, strlen(json));
}

// lwip is initialized by ziti_tunneler_init and cannot be initialized twice in one process (the second call never
// returns), so all test cases share one tunneler and each one only seeds the dns pool with its own address range
static tunneler_context dns_test_setup(const char *dns_ip, const char *cidr) {
    static netif_driver_t mock_netif = {};
    static tunneler_sdk_options tnlr_opts = {
            .l3_netif_driver = &mock_netif,
            .ziti_dial = ziti_sdk_c_dial,
            .ziti_close = ziti_sdk_c_close,
            .ziti_close_write = ziti_sdk_c_close_write,
            .ziti_write = ziti_sdk_c_write,
            .ziti_host = ziti_sdk_c_host
    };
    static tunneler_context tnlr = nullptr;
    if (tnlr == nullptr) {
        mock_netif.add_route = mock_add_route;
        mock_netif.delete_route = mock_delete_route;
        tnlr = ziti_tunneler_init(&tnlr_opts, uv_default_loop());
    }
    ziti_dns_setup(tnlr, dns_ip, cidr);
    return tnlr;
}

TEST_CASE("recycle ip", "[dns]") {
    dns_test_setup("100.64.0.2", "100.64.0.1/24");

    auto *mock_services = new model_map;
    auto *ips = new model_map;
    ziti_service *service;
    const ip_addr_t *ip;
    ziti_address za;

    uint32_t pool_size = (1 << (32 - 24)) - 4; // 24 bit prefix. subtract 4 for network, broadcast, tun, and dns IPs

    for (int i = 0; i < pool_size; i++) {
        service = new ziti_service;
        model_map_setl(mock_services, i, service); // dummy service to associate with hostname
        ziti_address_from_index(&za, i);
        ip = ziti_dns_register_hostname(&za, service);
        if (ip == nullptr) {
            break;
        }
        model_map_setl(ips, i, (ip_addr_t *)ip);
        printf("%s --> %s\n", za.addr.hostname, ipaddr_ntoa(ip));
    }

    // pool should be at capacity now, with most recent hostname mapped
    CHECK(ip != nullptr);

    // try to get one more IP while the pool is full
    ziti_address_from_string(&za, "just.one.more");
    CHECK(ziti_dns_register_hostname(&za, new ziti_service) == nullptr);

    // free up an IP and try again
    ziti_dns_deregister_intercept(model_map_getl(mock_services, 100));
    ip = ziti_dns_register_hostname(&za, new ziti_service);
    CHECK(ip != nullptr);
    CHECK_THAT(ipaddr_ntoa(ip), Catch::Equals("100.64.0.103"));

    // tun ip (.0.1), dns_ip (.0.2), network ip (.0.0), and broadcast ip (.0.255) should not be returned
    // first ip should not be tun or dns ip
    ip = static_cast<const ip_addr_t *>(model_map_getl(ips, 0));
    CHECK_THAT(ipaddr_ntoa(ip), Catch::Equals("100.64.0.3"));

    // last ip is not broadcast ip
    ip = static_cast<const ip_addr_t *>(model_map_getl(ips, pool_size-1));
    CHECK_THAT(ipaddr_ntoa(ip), Catch::Equals("100.64.0.254"));
}
static std::set<std::string> intercepted_names() {
    std::set<std::string> names;
    ziti_dns_foreach_intercepted_name([](const char *name, void *ctx) {
        static_cast<std::set<std::string> *>(ctx)->insert(name);
    }, &names);
    return names;
}

TEST_CASE("intercepted names", "[dns]") {
    dns_test_setup("100.72.0.2", "100.72.0.1/28");

    auto *host_svc = new ziti_service;
    auto *wild_svc = new ziti_service;
    ziti_address za;
    ziti_address_from_string(&za, "Storage.Example.NET");
    REQUIRE(ziti_dns_register_hostname(&za, host_svc) != nullptr);
    ziti_address_from_string(&za, "*.wild.example.org");
    CHECK(ziti_dns_register_hostname(&za, wild_svc) == nullptr);

    auto names = intercepted_names();
    CHECK(names.count("storage.example.net") == 1);
    CHECK(names.count("wild.example.org") == 1); // the domain, not the "*." pattern
    CHECK(names.count("*.wild.example.org") == 0);

    ziti_dns_deregister_intercept(host_svc);
    names = intercepted_names();
    CHECK(names.count("storage.example.net") == 0);
    CHECK(names.count("wild.example.org") == 1);

    ziti_dns_deregister_intercept(wild_svc);
    CHECK(intercepted_names().count("wild.example.org") == 0);
}

TEST_CASE("upstream presence", "[dns]") {
    CHECK_FALSE(ziti_dns_has_upstream());

    tunnel_upstream_dns fallback = {};
    fallback.host = (char *) "127.0.0.2";
    tunnel_upstream_dns *fallbacks[] = { &fallback, nullptr };
    REQUIRE(ziti_dns_set_fallback_upstream(uv_default_loop(), fallbacks) == 0);
    CHECK_FALSE(ziti_dns_has_upstream()); // found by the driver, not configured

    tunnel_upstream_dns upstream = {};
    upstream.host = (char *) "127.0.0.1";
    tunnel_upstream_dns *upstreams[] = { &upstream, nullptr };
    REQUIRE(ziti_dns_set_upstream(uv_default_loop(), upstreams) == 0);
    CHECK(ziti_dns_has_upstream());

    tunnel_upstream_dns *none[] = { nullptr };
    REQUIRE(ziti_dns_set_fallback_upstream(uv_default_loop(), none) == 0);
    CHECK(ziti_dns_has_upstream()); // a fallback never replaces it
}

// The leak checks below need the allocator statistics of AddressSanitizer (cmake -DZITI_TUNNEL_ASAN=ON).
// Without it the tests still run the same code, they just do not assert on memory.
#if defined(__SANITIZE_ADDRESS__)
#define DNS_TEST_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define DNS_TEST_ASAN 1
#endif
#endif

#ifdef DNS_TEST_ASAN
extern "C" size_t __sanitizer_get_current_allocated_bytes(void);
#define HEAP_IN_USE() ((long long) __sanitizer_get_current_allocated_bytes())
#else
#define HEAP_IN_USE() (0LL)
#endif

// a leaked DNS entry is over 300 bytes, and these tests would leak dozens of them
static const long long LEAK_TOLERANCE = 1024;

// The dns state is global and other test cases leave their hostnames and addresses behind. Registering a hostname that
// already exists only adds an intercept to the existing entry, so these tests use names of their own.
static void ziti_address_from_name(ziti_address *za, const char *prefix, uint32_t i) {
    static char json[64];
    snprintf(json, sizeof(json), "\"%s%03d.\"", prefix, i);
    parse_ziti_address(za, json, strlen(json));
}

TEST_CASE("deregistering a hostname releases its dns entry", "[dns]") {
    dns_test_setup("100.65.0.2", "100.65.0.1/28");

    const int hosts = 8;
    static int intercepts[hosts]; // the address of each one stands in for an intercept
    ziti_address za;

    auto cycle = [&]() {
        for (int i = 0; i < hosts; i++) {
            ziti_address_from_name(&za, "unreg", i);
            const ip_addr_t *ip = ziti_dns_register_hostname(&za, &intercepts[i]);
            REQUIRE(ip != nullptr);
            CHECK(ziti_dns_reverse_lookup(ipaddr_ntoa(ip)) != nullptr);
        }
        for (int i = 0; i < hosts; i++) {
            ziti_dns_deregister_intercept(&intercepts[i]);
        }
    };

    cycle(); // warm up: the maps reach their working size

    long long before = HEAP_IN_USE();
    for (int round = 0; round < 10; round++) {
        cycle();
    }
    long long growth = HEAP_IN_USE() - before;

#ifdef DNS_TEST_ASAN
    INFO("heap grew by " << growth << " bytes over 10 register/deregister rounds of " << hosts << " hostnames");
    CHECK(growth < LEAK_TOLERANCE);
#endif
    (void) growth;
}

TEST_CASE("a hostname that gets no ip does not leak a dns entry", "[dns]") {
    dns_test_setup("100.66.0.2", "100.66.0.1/28");

    // the range has 12 free addresses (16, minus network, broadcast, tun and dns): use them all up
    const int max_hosts = 64;
    static int intercepts[max_hosts];
    static int extra;
    ziti_address za;

    int registered = 0;
    while (registered < max_hosts) {
        ziti_address_from_name(&za, "nofree", registered);
        if (ziti_dns_register_hostname(&za, &intercepts[registered]) == nullptr) {
            break;
        }
        registered++;
    }
    REQUIRE(registered > 0);
    REQUIRE(registered < max_hosts); // the pool did run out

    // none of these new names can get an ip
    long long before = HEAP_IN_USE();
    for (int i = 0; i < 50; i++) {
        ziti_address_from_name(&za, "noip", i);
        CHECK(ziti_dns_register_hostname(&za, &extra) == nullptr);
    }
    long long growth = HEAP_IN_USE() - before;

#ifdef DNS_TEST_ASAN
    INFO("heap grew by " << growth << " bytes over 50 registrations that found no free ip");
    CHECK(growth < LEAK_TOLERANCE);
#endif
    (void) growth;

    for (int i = 0; i < registered; i++) {
        ziti_dns_deregister_intercept(&intercepts[i]);
    }
}

TEST_CASE("deregistering a wildcard domain releases it", "[dns]") {
    dns_test_setup("100.67.0.2", "100.67.0.1/28");

    static int intercept;
    ziti_address za;

    auto cycle = [&]() {
        ziti_address_from_name(&za, "*.wild", 0);
        // a wildcard domain gets no address of its own, the hostnames below it get theirs when they are looked up
        CHECK(ziti_dns_register_hostname(&za, &intercept) == nullptr);
        ziti_dns_deregister_intercept(&intercept);
    };

    cycle(); // warm up: the maps reach their working size

    long long before = HEAP_IN_USE();
    for (int round = 0; round < 20; round++) {
        cycle();
    }
    long long growth = HEAP_IN_USE() - before;

#ifdef DNS_TEST_ASAN
    INFO("heap grew by " << growth << " bytes over 20 register/deregister rounds of a wildcard domain");
    CHECK(growth < LEAK_TOLERANCE);
#endif
    (void) growth;
}
static void ziti_address_from_host(ziti_address *za, const char *host) {
    static char json[64];
    snprintf(json, sizeof(json), "\"%s\"", host);
    parse_ziti_address(za, json, strlen(json));
}

TEST_CASE("an entry with its own intercept follows the wildcard domain that covers it", "[dns]") {
    dns_test_setup("100.68.0.2", "100.68.0.1/28");

    static int host_intercept;
    static int domain_intercept;
    ziti_address host, wild;
    ziti_address_from_host(&host, "foo.covered.test");
    ziti_address_from_host(&wild, "*.covered.test");

    // the hostname has an intercept of its own and exists before the wildcard domain does
    const ip_addr_t *ip = ziti_dns_register_hostname(&host, &host_intercept);
    REQUIRE(ip != nullptr);
    CHECK(ziti_dns_reverse_lookup_domain(ip) == nullptr);

    CHECK(ziti_dns_register_hostname(&wild, &domain_intercept) == nullptr);
    const char *domain = ziti_dns_reverse_lookup_domain(ip);
    REQUIRE(domain != nullptr);
    CHECK_THAT(domain, Catch::Equals("*.covered.test"));

    // the service behind the wildcard is updated: its intercept goes away and is registered again. The entry stays,
    // because its own intercept does, and it must be covered by the new domain too.
    ziti_dns_deregister_intercept(&domain_intercept);
    CHECK(ziti_dns_reverse_lookup_domain(ip) == nullptr);
    CHECK(ziti_dns_register_hostname(&wild, &domain_intercept) == nullptr);
    domain = ziti_dns_reverse_lookup_domain(ip);
    REQUIRE(domain != nullptr);
    CHECK_THAT(domain, Catch::Equals("*.covered.test"));

    ziti_dns_deregister_intercept(&domain_intercept);
    ziti_dns_deregister_intercept(&host_intercept);
}

TEST_CASE("the last free ip of the pool is handed out", "[dns]") {
    dns_test_setup("100.69.0.2", "100.69.0.1/28");

    const int max_hosts = 64;
    static int intercepts[max_hosts];
    static int extra;
    ziti_address za;

    int registered = 0;
    while (registered < max_hosts) {
        ziti_address_from_name(&za, "lastip", registered);
        if (ziti_dns_register_hostname(&za, &intercepts[registered]) == nullptr) {
            break;
        }
        registered++;
    }
    REQUIRE(registered > 0);
    REQUIRE(registered < max_hosts); // the pool did run out

    // the address handed out last is free again: it is the only free one, and the last one the search looks at
    ziti_dns_deregister_intercept(&intercepts[registered - 1]);
    ziti_address_from_name(&za, "again", 0);
    CHECK(ziti_dns_register_hostname(&za, &extra) != nullptr);

    ziti_dns_deregister_intercept(&extra);
    for (int i = 0; i < registered - 1; i++) {
        ziti_dns_deregister_intercept(&intercepts[i]);
    }
}

// An identity with the services it dials, as far as the intercepts and dns names go: the ziti context only carries the
// instance, nothing connects to a controller.
struct test_identity {
    ziti_context ztx = nullptr;
    struct ziti_instance_s inst = {};

    test_identity() {
        ziti_config cfg = {};
        cfg.controller_url = const_cast<char *>("https://localhost:1");
        REQUIRE(ziti_context_init(&ztx, &cfg) == ZITI_OK);
        ziti_set_app_ctx(ztx, &inst);
    }
};

static ziti_service *new_intercept_service(const char *name, const char *hostname) {
    char cfg[256];
    snprintf(cfg, sizeof(cfg),
             "{\"protocols\":[\"tcp\"],\"addresses\":[\"%s\"],\"portRanges\":[{\"low\":80,\"high\":80}]}", hostname);
    auto *svc = new ziti_service();
    svc->name = strdup(name);
    svc->perm_flags = ZITI_CAN_DIAL;
    model_map_set(&svc->config, "intercept.v1", strdup(cfg));
    return svc;
}

TEST_CASE("removing an identity unregisters the dns names of its services", "[dns]") {
    tunneler_context tnlr = dns_test_setup("100.70.0.2", "100.70.0.1/28");
    test_identity id;

    // the first two names get the first two free addresses of the pool
    ziti_service *unavailable = new_intercept_service("rmid-unavailable", "unavailable.rmid.test");
    ziti_service *removed = new_intercept_service("rmid-removed", "removed.rmid.test");
    ziti_sdk_c_on_service(id.ztx, unavailable, ZITI_OK, tnlr);
    ziti_sdk_c_on_service(id.ztx, removed, ZITI_OK, tnlr);
    REQUIRE(model_map_size(&id.inst.intercepts) == 2);
    REQUIRE(ziti_dns_reverse_lookup("100.70.0.3") != nullptr);
    REQUIRE(ziti_dns_reverse_lookup("100.70.0.4") != nullptr);

    // a service that goes away takes its dns name with it
    ziti_sdk_c_on_service(id.ztx, unavailable, ZITI_SERVICE_UNAVAILABLE, tnlr);
    CHECK(model_map_size(&id.inst.intercepts) == 1);
    CHECK(ziti_dns_reverse_lookup("100.70.0.3") == nullptr);

    // so should removing the identity
    remove_intercepts(id.ztx, tnlr);
    CHECK(model_map_size(&id.inst.intercepts) == 0);
    CHECK(ziti_dns_reverse_lookup("100.70.0.4") == nullptr);
}

TEST_CASE("removing an identity releases its intercepts", "[dns]") {
    tunneler_context tnlr = dns_test_setup("100.71.0.2", "100.71.0.1/28");
    test_identity id;
    ziti_service *svc = new_intercept_service("rmid-leak", "leak.rmid.test");

    // heap growth over rounds of adding the intercept and then taking it away in the way given
    auto growth_of = [&](const std::function<void()> &take_away) {
        auto cycle = [&]() {
            ziti_sdk_c_on_service(id.ztx, svc, ZITI_OK, tnlr);
            take_away();
        };
        cycle(); // warm up: the maps reach their working size

        long long before = HEAP_IN_USE();
        for (int round = 0; round < 20; round++) {
            cycle();
        }
        return HEAP_IN_USE() - before;
    };

    // the service goes away: the way that already releases everything
    long long unavailable = growth_of([&]() { ziti_sdk_c_on_service(id.ztx, svc, ZITI_SERVICE_UNAVAILABLE, tnlr); });
    long long removed = growth_of([&]() { remove_intercepts(id.ztx, tnlr); });

#ifdef DNS_TEST_ASAN
    INFO("heap grew by " << unavailable << " bytes over 20 rounds of a service going away");
    CHECK(unavailable < LEAK_TOLERANCE);
    INFO("heap grew by " << removed << " bytes over 20 rounds of removing the identity");
    CHECK(removed < LEAK_TOLERANCE);
#endif
    (void) unavailable;
    (void) removed;
}
