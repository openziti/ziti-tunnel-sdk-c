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

// The controller reports an identity's name and id once the identity has authenticated, and the ziti context has
// nothing to say about them before that. Listing read them anyway and took the whole process down.
TEST_CASE("listing an identity that has not authenticated", "[ctrl]") {
    const ziti_tunnel_ctrl *ctrl = ziti_tunnel_init_cmd(uv_default_loop(), nullptr, nullptr);

    // nothing connects to a controller here, so the context has no identity data
    ziti_config cfg = {};
    cfg.controller_url = const_cast<char *>("https://localhost:1");
    ziti_context ztx = nullptr;
    REQUIRE(ziti_context_init(&ztx, &cfg) == ZITI_OK);
    REQUIRE(ziti_get_identity(ztx) == nullptr);

    struct ziti_instance_s *inst = new_ziti_instance("not-yet-authenticated");
    inst->ztx = ztx;
    set_ziti_instance(inst->identifier, inst);

    tunnel_command cmd = {};
    cmd.command = TunnelCommand_ListIdentities;
    list_result out;
    ctrl->process(&cmd, on_list_result, &out);

    remove_ziti_instance(inst->identifier);
    free(inst->identifier);
    free(inst);

    REQUIRE(out.called);
    INFO("listing: " << out.data);
    CHECK(out.success);
    // it is listed under the name it was loaded with; what only the controller knows is left out
    CHECK(out.data.find("\"Config\":\"not-yet-authenticated\"") != std::string::npos);
    CHECK(out.data.find("\"Name\"") == std::string::npos);
    CHECK(out.data.find("\"Id\"") == std::string::npos);
}
