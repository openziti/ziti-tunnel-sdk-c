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

TEST_CASE("recycle ip", "[dns]") {
    netif_driver_t mock_netif = {};
    mock_netif.add_route = mock_add_route;
    tunneler_sdk_options tnlr_opts = {
            .netif_driver = &mock_netif,
            .ziti_dial = ziti_sdk_c_dial,
            .ziti_close = ziti_sdk_c_close,
            .ziti_close_write = ziti_sdk_c_close_write,
            .ziti_write = ziti_sdk_c_write,
            .ziti_host = ziti_sdk_c_host
    };
    tunneler_context tnlr = ziti_tunneler_init(&tnlr_opts, uv_default_loop());
    ziti_dns_setup(tnlr, "100.64.0.2", "100.64.0.1/24");

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