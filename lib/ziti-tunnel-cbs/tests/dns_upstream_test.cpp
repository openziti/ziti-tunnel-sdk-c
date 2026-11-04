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

// End-to-end tests of forwarding DNS queries that are not intercepted to upstream resolvers.
// Queries enter the tunneler as IP packets through a fake netif driver, and responses are captured from it.
// The upstream resolvers are UDP servers on localhost that refuse or answer.
//
// These tests run a full tunneler (lwIP), which can be initialized only once per process. They are hidden ([.]),
// so they do not run with other tests that initialize a tunneler, and run in their own process (see CMakeLists.txt).

#include "catch2/catch.hpp"
#include <algorithm>
#include <cstring>
#include <string>
#include <vector>
#include <ziti/ziti_dns.h>

namespace {

const uint8_t TUN_IP[] = {100, 64, 0, 1};
const uint8_t DNS_IP[] = {100, 64, 0, 2};

struct fake_tun {
    packet_cb on_packet = nullptr;
    void *netif = nullptr;
    std::vector<uint8_t> response;
    int refresh_requests = 0;
} tun;

int tun_setup(netif_handle, uv_loop_t *, packet_cb cb, void *netif) {
    tun.on_packet = cb;
    tun.netif = netif;
    return 0;
}

ssize_t tun_write(netif_handle, const void *buf, size_t len) {
    tun.response.assign((const uint8_t *) buf, (const uint8_t *) buf + len);
    return (ssize_t) len;
}

int tun_route(netif_handle, const char *) {
    return 0;
}

void tun_refresh_fallback(netif_handle, uv_loop_t *) {
    tun.refresh_requests++;
}

tunneler_context tunneler() {
    static tunneler_context tnlr = nullptr;
    if (tnlr == nullptr) {
        static netif_driver_t driver{};
        driver.setup = tun_setup;
        driver.write = tun_write;
        driver.add_route = tun_route;
        driver.delete_route = tun_route;
        driver.dns_refresh_fallback = tun_refresh_fallback;

        tunneler_sdk_options opts{};
        opts.l3_netif_driver = &driver;
        opts.ziti_dial = ziti_sdk_c_dial;
        opts.ziti_close = ziti_sdk_c_close;
        opts.ziti_close_write = ziti_sdk_c_close_write;
        opts.ziti_write = ziti_sdk_c_write;
        opts.ziti_host = ziti_sdk_c_host;
        tnlr = ziti_tunneler_init(&opts, uv_default_loop());
    }
    // other tests may have pointed ziti_dns at another tunneler
    ziti_dns_setup(tnlr, "100.64.0.2", "100.64.0.1/24");
    return tnlr;
}

enum upstream_mode { REFUSE, ANSWER };

struct fake_upstream {
    uv_udp_t udp{};
    upstream_mode mode;
    uint64_t delay_ms;
    int queries = 0;
    struct sockaddr_storage addr{};
};

struct delayed_reply {
    uv_timer_t timer{};
    fake_upstream *upstream;
    std::vector<uint8_t> packet;
    struct sockaddr_storage peer{};
};

void upstream_alloc(uv_handle_t *, size_t, uv_buf_t *b) {
    static char buf[4096];
    *b = uv_buf_init(buf, sizeof(buf));
}

void send_reply(fake_upstream *up, std::vector<uint8_t> &packet, const struct sockaddr *peer) {
    uv_buf_t b = uv_buf_init((char *) packet.data(), packet.size());
    uv_udp_try_send(&up->udp, &b, 1, peer);
}

void on_reply_timer(uv_timer_t *t) {
    auto *r = static_cast<delayed_reply *>(t->data);
    send_reply(r->upstream, r->packet, (const struct sockaddr *) &r->peer);
    uv_close((uv_handle_t *) &r->timer, [](uv_handle_t *h) { delete static_cast<delayed_reply *>(h->data); });
}

void on_upstream_query(uv_udp_t *h, ssize_t len, const uv_buf_t *buf, const struct sockaddr *peer, unsigned) {
    auto *up = static_cast<fake_upstream *>(h->data);
    if (len < 12 || peer == nullptr) return;
    up->queries++;

    std::vector<uint8_t> reply(buf->base, buf->base + len);
    reply[2] |= 0x80;  // response
    reply[3] |= 0x80;  // recursion available
    if (up->mode == REFUSE) {
        reply[3] |= 5;
    } else {
        reply[7] = 1;  // one answer: name pointer, A, IN, ttl 60, 192.0.2.99
        const uint8_t answer[] = {0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 99};
        reply.insert(reply.end(), answer, answer + sizeof(answer));
    }

    auto *r = new delayed_reply;
    r->upstream = up;
    r->packet = reply;
    memcpy(&r->peer, peer, peer->sa_family == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in));
    uv_timer_init(h->loop, &r->timer);
    r->timer.data = r;
    uv_timer_start(&r->timer, on_reply_timer, up->delay_ms, 0);
}

fake_upstream *start_upstream(upstream_mode mode, uint64_t delay_ms = 0) {
    auto *up = new fake_upstream;
    up->mode = mode;
    up->delay_ms = delay_ms;
    up->udp.data = up;
    struct sockaddr_in local{};
    uv_ip4_addr("127.0.0.1", 0, &local);
    REQUIRE(uv_udp_init(uv_default_loop(), &up->udp) == 0);
    REQUIRE(uv_udp_bind(&up->udp, (const struct sockaddr *) &local, 0) == 0);
    int addrlen = sizeof(up->addr);
    REQUIRE(uv_udp_getsockname(&up->udp, (struct sockaddr *) &up->addr, &addrlen) == 0);
    REQUIRE(uv_udp_recv_start(&up->udp, upstream_alloc, on_upstream_query) == 0);
    return up;
}

void stop_upstream(fake_upstream *up) {
    uv_close((uv_handle_t *) &up->udp, [](uv_handle_t *h) { delete static_cast<fake_upstream *>(h->data); });
}

void use_fallback(std::vector<fake_upstream *> ups, uint64_t max_age_ms = 0) {
    // the age is measured from the loop time, which is not updated while tests run between loop iterations
    uv_update_time(uv_default_loop());
    std::vector<struct sockaddr_storage> addrs;
    for (auto *up : ups) addrs.push_back(up->addr);
    REQUIRE(ziti_dns_set_fallback_upstream(uv_default_loop(), addrs.data(), addrs.size(), max_age_ms) == 0);
}

uint16_t ip_checksum(const uint8_t *p, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < len; i += 2) sum += (p[i] << 8) | p[i + 1];
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t) ~sum;
}

// IPv4 + UDP (no checksum) + recursive DNS query for an A record
std::vector<uint8_t> dns_query_packet(const char *name, uint16_t id, uint16_t src_port) {
    std::vector<uint8_t> dns = {(uint8_t) (id >> 8), (uint8_t) id, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0};
    for (const char *label = name; *label;) {
        const char *dot = strchr(label, '.');
        size_t n = dot ? (size_t) (dot - label) : strlen(label);
        dns.push_back((uint8_t) n);
        dns.insert(dns.end(), label, label + n);
        label += n + (dot ? 1 : 0);
    }
    const uint8_t tail[] = {0, 0, 1, 0, 1};
    dns.insert(dns.end(), tail, tail + sizeof(tail));

    size_t udp_len = 8 + dns.size();
    size_t total = 20 + udp_len;
    std::vector<uint8_t> p = {0x45, 0, (uint8_t) (total >> 8), (uint8_t) total, 0, 0, 0, 0, 64, 17, 0, 0};
    p.insert(p.end(), TUN_IP, TUN_IP + 4);
    p.insert(p.end(), DNS_IP, DNS_IP + 4);
    uint16_t csum = ip_checksum(p.data(), 20);
    p[10] = csum >> 8;
    p[11] = csum & 0xff;
    const uint8_t udp[] = {(uint8_t) (src_port >> 8), (uint8_t) src_port, 0, 53,
                           (uint8_t) (udp_len >> 8), (uint8_t) udp_len, 0, 0};
    p.insert(p.end(), udp, udp + sizeof(udp));
    p.insert(p.end(), dns.begin(), dns.end());
    return p;
}

struct dns_result {
    bool answered = false;
    int rcode = -1;
    int answers = 0;
    double elapsed_ms = 0;
};

// send a query into the tunnel and run the loop until the response comes out, or the timeout passes
dns_result ask(const char *name, uint64_t timeout_ms = 3000) {
    static uint16_t id = 0x1000;
    static uint16_t port = 40000;
    id++;
    port++;

    tun.response.clear();
    uv_update_time(uv_default_loop());
    auto packet = dns_query_packet(name, id, port);
    uint64_t start = uv_hrtime();
    tun.on_packet((const char *) packet.data(), (ssize_t) packet.size(), tun.netif);

    uv_timer_t deadline;
    bool expired = false;
    uv_timer_init(uv_default_loop(), &deadline);
    deadline.data = &expired;
    uv_timer_start(&deadline, [](uv_timer_t *t) { *static_cast<bool *>(t->data) = true; }, timeout_ms, 0);
    while (tun.response.empty() && !expired) {
        uv_run(uv_default_loop(), UV_RUN_ONCE);
    }
    uv_close((uv_handle_t *) &deadline, nullptr);
    uv_run(uv_default_loop(), UV_RUN_NOWAIT);

    dns_result r;
    r.elapsed_ms = (double) (uv_hrtime() - start) / 1e6;
    if (tun.response.size() >= 20) {
        size_t dns = (tun.response[0] & 0xf) * 4 + 8;
        if (tun.response.size() >= dns + 12) {
            r.answered = true;
            r.rcode = tun.response[dns + 3] & 0xf;
            r.answers = (tun.response[dns + 6] << 8) | tun.response[dns + 7];
        }
    }
    return r;
}

}

TEST_CASE("fallback queries are forwarded to an upstream", "[upstream][.]") {
    tunneler();
    REQUIRE(tun.on_packet != nullptr);

    SECTION("an answer is forwarded") {
        auto *answer = start_upstream(ANSWER);
        use_fallback({answer});

        auto r = ask("www.example.test");
        CHECK(r.answered);
        CHECK(r.rcode == 0);
        CHECK(r.answers == 1);
        CHECK(answer->queries == 1);

        stop_upstream(answer);
    }

    SECTION("a failure is forwarded") {
        auto *refuse = start_upstream(REFUSE);
        use_fallback({refuse});

        auto r = ask("www.example.test");
        CHECK(r.answered);
        CHECK(r.rcode == 5);
        stop_upstream(refuse);
    }

    SECTION("without upstreams the query is refused") {
        use_fallback({});

        auto r = ask("www.example.test");
        CHECK(r.answered);
        CHECK(r.rcode == 5);
    }

    use_fallback({});
}

TEST_CASE("a stale fallback is refreshed when it is used", "[upstream][.]") {
    tunneler();
    REQUIRE(tun.on_packet != nullptr);

    auto *answer = start_upstream(ANSWER);
    use_fallback({answer}, 500);
    tun.refresh_requests = 0;

    // fresh: forwarded without a refresh
    auto r = ask("www.example.test");
    CHECK(r.rcode == 0);
    CHECK(tun.refresh_requests == 0);

    // stale: still forwarded with the current servers, and a refresh is requested
    uv_sleep(600);
    r = ask("www.example.test");
    CHECK(r.rcode == 0);
    CHECK(r.answers == 1);
    CHECK(tun.refresh_requests == 1);

    // only once per period, even before the driver provided the new servers
    r = ask("www.example.test");
    CHECK(tun.refresh_requests == 1);

    // a new list restarts the period
    use_fallback({answer}, 500);
    uv_sleep(600);
    ask("www.example.test");
    CHECK(tun.refresh_requests == 2);

    // a refresh age of 0 never refreshes
    use_fallback({answer}, 0);
    uv_sleep(600);
    ask("www.example.test");
    CHECK(tun.refresh_requests == 2);

    use_fallback({});
    stop_upstream(answer);
    uv_run(uv_default_loop(), UV_RUN_NOWAIT);
}

static std::vector<std::string> intercepted_names() {
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

static bool has_name(const char *name) {
    auto names = intercepted_names();
    return std::find(names.begin(), names.end(), name) != names.end();
}

TEST_CASE("a hostname resolved from a wildcard and then intercepted stays routed", "[upstream][.]") {
    tunneler();
    REQUIRE(tun.on_packet != nullptr);

    int wildcard_svc, host_svc;
    ziti_address addr;
    REQUIRE(ziti_address_from_string(&addr, "*.wild.example"));
    ziti_dns_register_hostname(&addr, &wildcard_svc);

    // the lookup creates an entry for the name, linked to the wildcard domain
    auto r = ask("app.wild.example");
    CHECK(r.rcode == 0);
    CHECK(r.answers == 1);
    CHECK_FALSE(has_name("app.wild.example"));  // covered by wild.example

    // a service intercepts the same name explicitly
    REQUIRE(ziti_address_from_string(&addr, "app.wild.example"));
    ziti_dns_register_hostname(&addr, &host_svc);

    // without the wildcard, the name must still be routed to the tunneler
    ziti_dns_deregister_intercept(&wildcard_svc);
    CHECK(has_name("app.wild.example"));
    CHECK_FALSE(has_name("wild.example"));

    ziti_dns_deregister_intercept(&host_svc);
    CHECK_FALSE(has_name("app.wild.example"));
}
