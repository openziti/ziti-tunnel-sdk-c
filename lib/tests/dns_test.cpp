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
#include "ziti/ziti_tunnel.h"
#include "ziti/ziti_tunnel_cbs.h"
#include "ziti/ziti_dns.h"
#include "ziti/model_collections.h"

static int mock_add_route(netif_handle tun, const char *dest) {
    return 0;
}

static void ziti_address_from_index(ziti_address *za, uint32_t i) {
    static char json[32];
    snprintf(json, sizeof(json), "\"host%03d.\"", i);
    parse_ziti_address(za, json, strlen(json));
}

// lwip is initialized by ziti_tunneler_init and cannot be initialized twice in one process (the second call never
// returns), so all test cases share one tunneler and each one only seeds the dns pool with its own address range
static void dns_test_setup(const char *dns_ip, const char *cidr) {
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
        tnlr = ziti_tunneler_init(&tnlr_opts, uv_default_loop());
    }
    ziti_dns_setup(tnlr, dns_ip, cidr);
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