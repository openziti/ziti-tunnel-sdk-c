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

#include <string>

#include "catch2/catch.hpp"
#include "ziti/ziti_tunnel_cbs.h"

struct list_result {
    bool called = false;
    bool success = false;
    std::string data;
};

static void on_list_result(const tunnel_result *res, void *ctx) {
    auto *out = static_cast<list_result *>(ctx);
    out->called = true;
    out->success = res->success;
    out->data = res->data ? res->data : "";
}

static void on_tunnel_event(const base_event *) {}

// The controller reports an identity's name and id once the identity has authenticated, and the ziti context has
// nothing to say about them before that. Listing read them anyway and took the whole process down.
TEST_CASE("listing an identity that has not authenticated", "[ctrl]") {
    uv_loop_t *loop = uv_default_loop();
    // the SIGUSR1 handle this sets up stays with the loop for good, which is fine because setting it up is idempotent
    const ziti_tunnel_ctrl *ctrl = ziti_tunnel_init_cmd(loop, nullptr, on_tunnel_event);

    // a disabled identity never reaches the controller: it has no identity data, and its context never
    // initializes the controller, so the context itself has no URL to report either
    ziti_config cfg = {};
    cfg.controller_url = const_cast<char *>("https://localhost:1");
    ziti_options opts = {};
    opts.disabled = true;

    struct ziti_instance_s *inst = new_ziti_instance("not-yet-authenticated");
    REQUIRE(init_ziti_instance(inst, &cfg, &opts) == ZITI_OK);
    REQUIRE(ziti_context_run(inst->ztx, loop) == ZITI_OK);
    set_ziti_instance(inst->identifier, inst);
    REQUIRE(ziti_get_identity(inst->ztx) == nullptr);
    REQUIRE(std::string(ziti_get_controller(inst->ztx)).empty());

    tunnel_command cmd = {};
    cmd.command = TunnelCommand_ListIdentities;
    list_result out;
    ctrl->process(&cmd, on_list_result, &out);

    REQUIRE(out.called);
    INFO("listing: " << out.data);
    CHECK(out.success);
    // it is listed under the name it was loaded with, and on the controller it was configured with;
    // what only the controller knows is left out
    CHECK(out.data.find("\"Config\":\"not-yet-authenticated\"") != std::string::npos);
    CHECK(out.data.find("\"Network\":\"https://localhost:1\"") != std::string::npos);
    CHECK(out.data.find("\"Name\"") == std::string::npos);
    CHECK(out.data.find("\"Id\"") == std::string::npos);

    // the context is freed by the loop once it has shut down, and it reports on its way out to the instance
    remove_ziti_instance(inst->identifier);
    REQUIRE(ziti_shutdown(inst->ztx) == ZITI_OK);
    for (int i = 0; i < 10 && uv_loop_alive(loop); i++) {
        uv_run(loop, UV_RUN_NOWAIT);
    }
    free(inst->identifier);
    free(inst->controller_url);
    free(inst);
}

static const ziti_tunnel_ctrl *ctrl() {
    return ziti_tunnel_init_cmd(uv_default_loop(), nullptr, on_tunnel_event);
}

// an identity that is loaded and listed, with a context that has no identity data because nothing connects to a controller
struct listed_instance {
    struct ziti_instance_s *inst;

    explicit listed_instance(const char *name) : inst(new_ziti_instance(name)) {
        ziti_config cfg = {};
        cfg.controller_url = const_cast<char *>("https://localhost:1");
        REQUIRE(ziti_context_init(&inst->ztx, &cfg) == ZITI_OK);
        set_ziti_instance(inst->identifier, inst);
    }

    ~listed_instance() {
        remove_ziti_instance(inst->identifier);
        free(inst->identifier);
        free(inst);
    }
};

// not called list(): the ziti headers define a macro that turns it into model_list
static list_result list_identities() {
    tunnel_command cmd = {};
    cmd.command = TunnelCommand_ListIdentities;
    list_result out;
    ctrl()->process(&cmd, on_list_result, &out);
    return out;
}

// the {...} object of the listing that holds the given Config: a row has no nested objects
static std::string row(const std::string &data, const char *config) {
    size_t at = data.find(std::string("\"Config\":\"") + config + "\"");
    REQUIRE(at != std::string::npos);
    size_t begin = data.rfind('{', at);
    size_t end = data.find('}', at);
    REQUIRE(begin != std::string::npos);
    REQUIRE(end != std::string::npos);
    return data.substr(begin, end - begin + 1);
}

TEST_CASE("each listed identity carries its own state", "[ctrl]") {
    listed_instance a("state-first"), b("state-second");
    ziti_event_t prompt = {};
    prompt.type = ZitiAuthEvent;
    prompt.auth.action = ziti_auth_prompt_totp;
    ziti_event_t ok = {};
    ok.type = ZitiContextEvent;
    ok.ctx.ctrl_status = ZITI_OK;
    ziti_instance_apply_event(a.inst, &prompt);
    ziti_instance_apply_event(b.inst, &ok);

    list_result out = list_identities();
    REQUIRE(out.called);
    INFO("listing: " << out.data);
    std::string first = row(out.data, "state-first");
    std::string second = row(out.data, "state-second");
    CHECK(first.find("\"AuthState\":\"partial\"") != std::string::npos);
    CHECK(first.find("\"AuthNeeds\":\"totp_code\"") != std::string::npos);
    CHECK(first.find("\"MfaEnrolled\":\"enrolled\"") != std::string::npos);
    CHECK(second.find("\"AuthState\":\"authenticated\"") != std::string::npos);
    CHECK(second.find("\"AuthNeeds\":\"none\"") != std::string::npos);
    CHECK(second.find("\"MfaEnrolled\":null") != std::string::npos);
}

TEST_CASE("a listed identity has no state before any signal", "[ctrl]") {
    listed_instance li("state-unknown");
    list_result out = list_identities();
    REQUIRE(out.called);
    CHECK(out.data.find("\"AuthState\":null") != std::string::npos);
    CHECK(out.data.find("\"AuthNeeds\":null") != std::string::npos);
    CHECK(out.data.find("\"MfaEnrolled\":null") != std::string::npos);
}
