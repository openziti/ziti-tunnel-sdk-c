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
#include <map>
#include <string>
#include <vector>
#include "catch2/catch.hpp"
#include "ziti/ziti_tunnel.h"
#include "ziti/ziti_tunnel_cbs.h"
#include "ziti_hosting.h"
extern "C" {
#include "ziti_instance.h"
}
#include "test_tunneler.h"

#define HOST_V1 R"({"protocol":"tcp","address":"127.0.0.1","port":9})"

static int host_calls = 0;
static int host_marker;

static host_ctx_t *counting_host(void *ziti_ctx, tunneler_context tnlr_ctx, const char *service_name,
                                 cfg_type_e cfg_type, const void *cfg) {
    host_calls++;
    return reinterpret_cast<host_ctx_t *>(&host_marker); // opaque here, never dereferenced
}

// stands in for ziti_sdk_c_host under on_service: hosting nothing, it leaves on_service nothing to keep
static host_ctx_t *refusing_host(void *ziti_ctx, tunneler_context tnlr_ctx, const char *service_name,
                                 cfg_type_e cfg_type, const void *cfg) {
    host_calls++;
    return nullptr;
}

// stands in for ziti_sdk_c_host with a host that on_service keeps. it has no server connection, so stop_hosting's
// ziti_close() fails without calling back, and the host is never freed: a few bytes per test case.
static host_ctx_t *keeping_host(void *ziti_ctx, tunneler_context tnlr_ctx, const char *service_name,
                                cfg_type_e cfg_type, const void *cfg) {
    host_calls++;
    auto *host = static_cast<host_ctx_t *>(calloc(1, sizeof(host_ctx_t)));
    host->service_name = strdup(service_name);
    return host;
}

// stand in for the SDK's service cache, which the context here never fills
static std::map<std::string, ziti_service *> sdk_services;
static std::vector<std::string> looked_up;
static std::vector<std::function<void()>> unanswered;

// answers before it returns, as ziti_service_available() does for a cached service
static int cached_lookup(ziti_context ztx, const char *name, ziti_service_cb cb, void *ctx) {
    looked_up.emplace_back(name);
    cb(ztx, sdk_services.at(name), ZITI_OK, ctx);
    return ZITI_OK;
}

// answers when the test says so, as ziti_service_available() does when it has to ask the controller
static int late_lookup(ziti_context ztx, const char *name, ziti_service_cb cb, void *ctx) {
    looked_up.emplace_back(name);
    ziti_service *svc = sdk_services.at(name);
    unanswered.emplace_back([=] { cb(ztx, svc, ZITI_OK, ctx); });
    return ZITI_OK;
}

static void rehost(ziti_context ztx, const ziti_service *svc, int status, void *tnlr_ctx) {
    ziti_sdk_c_on_service(ztx, const_cast<ziti_service *>(svc), status, tnlr_ctx);
}

// sets the mode, and the host function the shared tunneler uses, for one test case, and puts both back afterwards
struct tunneler_mode {
    tunneler_context tnlr = test_tunneler();
    ziti_sdk_host_cb saved_host = tnlr->opts.ziti_host;

    explicit tunneler_mode(bool intercept_only, ziti_sdk_host_cb host = refusing_host) {
        ziti_tunnel_set_intercept_only(intercept_only);
        tnlr->opts.ziti_host = host;
        host_calls = 0;
        sdk_services.clear();
        looked_up.clear();
        unanswered.clear();
    }

    ~tunneler_mode() {
        ziti_tunnel_set_intercept_only(false);
        tnlr->opts.ziti_host = saved_host;
    }
};

static ziti_service *new_service(const char *name, int perm_flags, const char *host_cfg, const char *intercept_cfg) {
    auto *svc = new ziti_service();
    svc->name = strdup(name);
    svc->perm_flags = perm_flags;
    model_map_set(&svc->config, "host.v1", strdup(host_cfg));
    if (intercept_cfg) {
        model_map_set(&svc->config, "intercept.v1", strdup(intercept_cfg));
    }
    return svc;
}

static bool held_back(const test_identity &id, const char *service) {
    return model_map_get(&id.inst.unhosted, service) != nullptr;
}

// the service as the SDK reports it: in its cache, then handed to on_service
static ziti_service *offer(const test_identity &id, tunneler_context tnlr, ziti_service *svc) {
    sdk_services[svc->name] = svc;
    ziti_sdk_c_on_service(id.ztx, svc, ZITI_OK, tnlr);
    return svc;
}

// what the switch does for one identity, with the SDK's lookup stood in for
static size_t switch_identity(test_identity &id, tunneler_context tnlr, bool intercept_only,
                              service_lookup_fn lookup = cached_lookup) {
    ziti_tunneler_set_intercept_only(tnlr, intercept_only);
    return apply_intercept_only(&id.inst, tnlr, lookup, rehost);
}

#define INTERCEPT_V1(ip) R"({"protocols":["tcp"],"addresses":[")" ip R"("],"portRanges":[{"low":80,"high":80}]})"

// a tunneler built by hand, so the check in ziti_tunneler_host is tested apart from the one in on_service
TEST_CASE("ziti_tunneler_host never hosts for an intercept-only tunneler", "[intercept-only]") {
    struct tunneler_ctx_s ctx = {};
    ctx.opts.ziti_host = counting_host;
    host_calls = 0;

    CHECK_FALSE(ziti_tunneler_is_intercept_only(&ctx));
    CHECK(ziti_tunneler_host(&ctx, nullptr, "svc", HOST_CFG_V1, nullptr) == reinterpret_cast<host_ctx_t *>(&host_marker));
    CHECK(host_calls == 1);

    ziti_tunneler_set_intercept_only(&ctx, true);
    CHECK(ziti_tunneler_is_intercept_only(&ctx));
    CHECK(ziti_tunneler_host(&ctx, nullptr, "svc", HOST_CFG_V1, nullptr) == nullptr);
    CHECK(host_calls == 1);
}

TEST_CASE("the mode set before ziti_tunnel_init_cmd applies when it runs", "[intercept-only]") {
    tunneler_context tnlr = test_tunneler();
    ziti_tunnel_init_cmd(uv_default_loop(), nullptr, [](const base_event *) {});

    ziti_tunnel_set_intercept_only(true);
    CHECK_FALSE(ziti_tunneler_is_intercept_only(tnlr));
    test_tunneler(); // gives the command layer its tunneler again
    CHECK(ziti_tunneler_is_intercept_only(tnlr));

    ziti_tunnel_set_intercept_only(false);
    CHECK_FALSE(ziti_tunneler_is_intercept_only(tnlr));
}

TEST_CASE("a default tunneler hosts a service it may bind", "[intercept-only]") {
    tunneler_mode mode(false);
    test_identity id;

    ziti_sdk_c_on_service(id.ztx, new_service("io-default", ZITI_CAN_BIND, HOST_V1, nullptr), ZITI_OK, mode.tnlr);
    CHECK(host_calls == 1);
}

TEST_CASE("an intercept-only tunneler never hosts a service it may bind", "[intercept-only]") {
    tunneler_mode mode(true);
    test_identity id;

    // added, then changed
    const char *configs[] = { HOST_V1, R"({"protocol":"tcp","address":"127.0.0.1","port":10})" };
    for (const char *cfg : configs) {
        ziti_sdk_c_on_service(id.ztx, new_service("io-bind", ZITI_CAN_BIND, cfg, nullptr), ZITI_OK, mode.tnlr);
    }
    CHECK(host_calls == 0);
    CHECK(model_map_size(&id.inst.hosts) == 0);
    CHECK(held_back(id, "io-bind"));
}

TEST_CASE("a held back service is forgotten when it goes away or can no longer be bound", "[intercept-only]") {
    tunneler_mode mode(true);
    test_identity id;
    ziti_service *svc = new_service("io-forget", ZITI_CAN_BIND, HOST_V1, nullptr);

    ziti_sdk_c_on_service(id.ztx, svc, ZITI_OK, mode.tnlr);
    REQUIRE(held_back(id, "io-forget"));
    ziti_sdk_c_on_service(id.ztx, svc, ZITI_SERVICE_UNAVAILABLE, mode.tnlr);
    CHECK_FALSE(held_back(id, "io-forget"));

    ziti_sdk_c_on_service(id.ztx, svc, ZITI_OK, mode.tnlr);
    REQUIRE(held_back(id, "io-forget"));
    svc->perm_flags = ZITI_CAN_DIAL;
    ziti_sdk_c_on_service(id.ztx, svc, ZITI_OK, mode.tnlr);
    CHECK_FALSE(held_back(id, "io-forget"));
}

TEST_CASE("turning intercept-only on stops what every identity hosts", "[intercept-only]") {
    tunneler_mode mode(false, keeping_host);
    registered_identity a("io-on-a"), b("io-on-b");
    ziti_sdk_c_on_service(a.ztx, new_service("io-on-a-svc", ZITI_CAN_BIND, HOST_V1, nullptr), ZITI_OK, mode.tnlr);
    ziti_sdk_c_on_service(b.ztx, new_service("io-on-b-svc", ZITI_CAN_BIND, HOST_V1, nullptr), ZITI_OK, mode.tnlr);
    REQUIRE(model_map_size(&a.inst.hosts) == 1);
    REQUIRE(model_map_size(&b.inst.hosts) == 1);

    ziti_tunnel_set_intercept_only(true);
    CHECK(model_map_size(&a.inst.hosts) == 0);
    CHECK(model_map_size(&b.inst.hosts) == 0);
    CHECK(held_back(a, "io-on-a-svc"));
    CHECK(held_back(b, "io-on-b-svc"));

    // again: nothing changes
    ziti_tunnel_set_intercept_only(true);
    CHECK(model_map_size(&a.inst.hosts) == 0);
    CHECK(model_map_size(&b.inst.hosts) == 0);
    CHECK(held_back(a, "io-on-a-svc"));
    CHECK(held_back(b, "io-on-b-svc"));
    CHECK(host_calls == 2);
}

TEST_CASE("the switch brings a tunneler whose own flag was set apart into line", "[intercept-only]") {
    tunneler_mode mode(false, keeping_host);
    registered_identity id("io-apart");
    ziti_sdk_c_on_service(id.ztx, new_service("io-apart-svc", ZITI_CAN_BIND, HOST_V1, nullptr), ZITI_OK, mode.tnlr);
    REQUIRE(model_map_size(&id.inst.hosts) == 1);

    ziti_tunneler_set_intercept_only(mode.tnlr, true);
    ziti_tunnel_set_intercept_only(true);
    CHECK(model_map_size(&id.inst.hosts) == 0);
    CHECK(held_back(id, "io-apart-svc"));

    ziti_tunnel_set_intercept_only(false);
    ziti_tunneler_set_intercept_only(mode.tnlr, true);
    ziti_tunnel_set_intercept_only(false);
    CHECK_FALSE(ziti_tunneler_is_intercept_only(mode.tnlr));
}

TEST_CASE("turning intercept-only on stops the host of a service it may dial and bind, and keeps the intercept",
          "[intercept-only]") {
    tunneler_mode mode(false, keeping_host);
    registered_identity id("io-db-on");
    ziti_sdk_c_on_service(id.ztx, new_service("io-db-on-svc", ZITI_CAN_DIAL | ZITI_CAN_BIND, HOST_V1,
                                              INTERCEPT_V1("100.72.0.11")), ZITI_OK, mode.tnlr);
    REQUIRE(model_map_size(&id.inst.intercepts) == 1);
    REQUIRE(model_map_size(&id.inst.hosts) == 1);

    ziti_tunnel_set_intercept_only(true);
    CHECK(model_map_size(&id.inst.hosts) == 0);
    CHECK(model_map_size(&id.inst.intercepts) == 1);
    CHECK(held_back(id, "io-db-on-svc"));
    remove_intercepts(id.ztx, mode.tnlr);
}

TEST_CASE("turning intercept-only off commits the routes once, only when it asked for services", "[intercept-only]") {
    tunneler_mode mode(true);
    registered_identity a("io-commit-a"), b("io-commit-b");
    ziti_sdk_c_on_service(a.ztx, new_service("io-commit-a-svc", ZITI_CAN_BIND, HOST_V1, nullptr), ZITI_OK, mode.tnlr);
    ziti_sdk_c_on_service(b.ztx, new_service("io-commit-b-svc", ZITI_CAN_BIND, HOST_V1, nullptr), ZITI_OK, mode.tnlr);
    int commits = test_route_commits;

    ziti_tunnel_set_intercept_only(false);
    CHECK(test_route_commits == commits + 1);

    ziti_tunnel_set_intercept_only(true);
    ziti_tunnel_set_intercept_only(false);
    CHECK(test_route_commits == commits + 1);
}

TEST_CASE("a held back service follows its dial and bind permissions", "[intercept-only]") {
    tunneler_mode mode(true);
    test_identity id;
    ziti_service *svc = new_service("io-db-perms", ZITI_CAN_DIAL | ZITI_CAN_BIND, HOST_V1, INTERCEPT_V1("100.72.0.12"));
    ziti_sdk_c_on_service(id.ztx, svc, ZITI_OK, mode.tnlr);
    REQUIRE(model_map_size(&id.inst.intercepts) == 1);
    REQUIRE(held_back(id, "io-db-perms"));

    svc->perm_flags = ZITI_CAN_BIND;
    ziti_sdk_c_on_service(id.ztx, svc, ZITI_OK, mode.tnlr);
    CHECK(model_map_size(&id.inst.intercepts) == 0);
    CHECK(held_back(id, "io-db-perms"));

    svc->perm_flags = ZITI_CAN_DIAL | ZITI_CAN_BIND;
    ziti_sdk_c_on_service(id.ztx, svc, ZITI_OK, mode.tnlr);
    svc->perm_flags = ZITI_CAN_DIAL;
    ziti_sdk_c_on_service(id.ztx, svc, ZITI_OK, mode.tnlr);
    CHECK(model_map_size(&id.inst.intercepts) == 1);
    CHECK_FALSE(held_back(id, "io-db-perms"));
    CHECK(host_calls == 0);
    remove_intercepts(id.ztx, mode.tnlr);
}

TEST_CASE("a service held back by two identities is held back by each", "[intercept-only]") {
    tunneler_mode mode(false, keeping_host);
    registered_identity a("io-shared-a"), b("io-shared-b");
    ziti_service *svc_a = new_service("io-shared", ZITI_CAN_BIND, HOST_V1, nullptr);
    ziti_sdk_c_on_service(a.ztx, svc_a, ZITI_OK, mode.tnlr);
    ziti_sdk_c_on_service(b.ztx, new_service("io-shared", ZITI_CAN_BIND, HOST_V1, nullptr), ZITI_OK, mode.tnlr);

    ziti_tunnel_set_intercept_only(true);
    REQUIRE(held_back(a, "io-shared"));
    REQUIRE(held_back(b, "io-shared"));

    ziti_sdk_c_on_service(a.ztx, svc_a, ZITI_SERVICE_UNAVAILABLE, mode.tnlr);
    CHECK_FALSE(held_back(a, "io-shared"));
    CHECK(held_back(b, "io-shared"));
}

TEST_CASE("turning intercept-only off asks the SDK again for each service held back, and hosts it",
          "[intercept-only]") {
    tunneler_mode mode(true, keeping_host);
    test_identity id;
    offer(id, mode.tnlr, new_service("io-again-a", ZITI_CAN_BIND, HOST_V1, nullptr));
    offer(id, mode.tnlr, new_service("io-again-b", ZITI_CAN_BIND, HOST_V1, nullptr));
    REQUIRE(host_calls == 0);

    CHECK(switch_identity(id, mode.tnlr, false) == 2);
    CHECK(looked_up.size() == 2);
    CHECK(host_calls == 2);
    CHECK(model_map_size(&id.inst.hosts) == 2);
    CHECK(model_map_size(&id.inst.unhosted) == 0);
}

TEST_CASE("an answer that comes after intercept-only is back on hosts nothing", "[intercept-only]") {
    tunneler_mode mode(true, keeping_host);
    test_identity id;
    offer(id, mode.tnlr, new_service("io-late", ZITI_CAN_BIND, HOST_V1, nullptr));

    switch_identity(id, mode.tnlr, false, late_lookup);
    REQUIRE(unanswered.size() == 1);
    switch_identity(id, mode.tnlr, true);
    for (auto &answer : unanswered) {
        answer();
    }
    CHECK(host_calls == 0);
    CHECK(model_map_size(&id.inst.hosts) == 0);
    CHECK(held_back(id, "io-late"));
}

TEST_CASE("services that change while intercept-only is on are hosted as they are when it turns off",
          "[intercept-only]") {
    tunneler_mode mode(false, keeping_host);
    test_identity id;
    offer(id, mode.tnlr, new_service("io-walk-a", ZITI_CAN_BIND, HOST_V1, nullptr));
    ziti_service *b = offer(id, mode.tnlr, new_service("io-walk-b", ZITI_CAN_BIND, HOST_V1, nullptr));
    REQUIRE(model_map_size(&id.inst.hosts) == 2);
    switch_identity(id, mode.tnlr, true);
    REQUIRE(model_map_size(&id.inst.unhosted) == 2);

    // a's host config changes, b can no longer be bound
    offer(id, mode.tnlr, new_service("io-walk-a", ZITI_CAN_BIND, R"({"protocol":"tcp","address":"127.0.0.1","port":10})", nullptr));
    b->perm_flags = ZITI_CAN_DIAL;
    ziti_sdk_c_on_service(id.ztx, b, ZITI_OK, mode.tnlr);

    CHECK(switch_identity(id, mode.tnlr, false) == 1);
    CHECK(looked_up == std::vector<std::string>{"io-walk-a"});
    CHECK(model_map_size(&id.inst.hosts) == 1);
    CHECK(model_map_get(&id.inst.hosts, "io-walk-a") != nullptr);

    switch_identity(id, mode.tnlr, true);
    CHECK(model_map_size(&id.inst.hosts) == 0);
    CHECK(model_map_size(&id.inst.unhosted) == 1);
    CHECK(host_calls == 3);
}

TEST_CASE("a host the switch never reached stops at its service's next event", "[intercept-only]") {
    tunneler_mode mode(false, keeping_host);
    test_identity id; // not one the command layer knows, so the switch can't reach it, but its next service event can
    ziti_service *svc = new_service("io-unseen", ZITI_CAN_BIND, HOST_V1, nullptr);
    ziti_sdk_c_on_service(id.ztx, svc, ZITI_OK, mode.tnlr);
    REQUIRE(model_map_size(&id.inst.hosts) == 1);

    ziti_tunnel_set_intercept_only(true);
    REQUIRE(model_map_size(&id.inst.hosts) == 1);
    ziti_sdk_c_on_service(id.ztx, svc, ZITI_OK, mode.tnlr);
    CHECK(model_map_size(&id.inst.hosts) == 0);
    CHECK(held_back(id, "io-unseen"));
    CHECK(host_calls == 1);
}

// the context never connects, so the SDK can't hand the held back services over again and none is hosted here. that
// they are hosted again once the SDK has them is checked against a controller.
TEST_CASE("turning intercept-only off releases the services held back", "[intercept-only]") {
    tunneler_mode mode(true);
    registered_identity id("io-off");
    ziti_sdk_c_on_service(id.ztx, new_service("io-off-svc", ZITI_CAN_BIND, HOST_V1, nullptr), ZITI_OK, mode.tnlr);
    REQUIRE(held_back(id, "io-off-svc"));

    ziti_tunnel_set_intercept_only(false);
    CHECK(model_map_size(&id.inst.unhosted) == 0);
}

TEST_CASE("turning intercept-only off skips an identity whose context isn't loaded", "[intercept-only]") {
    tunneler_mode mode(true);
    registered_identity id("io-unloaded");
    ziti_sdk_c_on_service(id.ztx, new_service("io-unloaded-svc", ZITI_CAN_BIND, HOST_V1, nullptr), ZITI_OK, mode.tnlr);
    REQUIRE(held_back(id, "io-unloaded-svc"));
    id.inst.ztx = nullptr;

    ziti_tunnel_set_intercept_only(false);
    CHECK(held_back(id, "io-unloaded-svc"));
}

TEST_CASE("an intercept-only tunneler still intercepts a service it may dial and bind", "[intercept-only]") {
    tunneler_mode mode(true);
    test_identity id;
    const char *intercept = R"({"protocols":["tcp"],"addresses":["100.72.0.10"],"portRanges":[{"low":80,"high":80}]})";

    ziti_sdk_c_on_service(id.ztx, new_service("io-dial-bind", ZITI_CAN_DIAL | ZITI_CAN_BIND, HOST_V1, intercept),
                          ZITI_OK, mode.tnlr);
    CHECK(model_map_size(&id.inst.intercepts) == 1);
    CHECK(host_calls == 0);
    CHECK(model_map_size(&id.inst.hosts) == 0);
    remove_intercepts(id.ztx, mode.tnlr);
}

TEST_CASE("the SetInterceptOnly command carries the mode, and reads no mode when it is missing", "[intercept-only]") {
    tunnel_command cmd = {};
    const char *json = R"({"Command":"SetInterceptOnly","Data":{"InterceptOnly":true}})";
    REQUIRE(parse_tunnel_command(&cmd, json, strlen(json)) > 0);
    CHECK(cmd.command == TunnelCommand_SetInterceptOnly);

    tunnel_set_intercept_only req = {};
    REQUIRE(parse_tunnel_set_intercept_only(&req, cmd.data, strlen(cmd.data)) > 0);
    REQUIRE(req.intercept_only != nullptr);
    CHECK(*req.intercept_only);
    free_tunnel_set_intercept_only(&req);
    free_tunnel_command(&cmd);

    // a missing value must not read as false, which would turn the mode off
    REQUIRE(parse_tunnel_set_intercept_only(&req, "{}", 2) >= 0);
    CHECK(req.intercept_only == nullptr);
    free_tunnel_set_intercept_only(&req);
}
