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

#ifndef ZITI_TUNNEL_SDK_TEST_TUNNELER_H
#define ZITI_TUNNEL_SDK_TEST_TUNNELER_H

#include <string>
#include "catch2/catch.hpp"
#include "ziti/ziti_tunnel.h"
#include "ziti/ziti_tunnel_cbs.h"

// lwip is initialized by ziti_tunneler_init() and cannot be initialized twice in one process (the second call never
// returns), so all test cases share one tunneler. Each call also hands it to the command layer (ziti_tunnel_init_cmd).
tunneler_context test_tunneler();

// how many times the shared tunneler has committed its routes
extern int test_route_commits;

// An identity, as far as the intercepts, hosts and dns names of its services go: the ziti context only carries the
// instance, nothing connects to a controller.
struct test_identity {
    ziti_context ztx = nullptr;
    struct ziti_instance_s inst = {};

    test_identity() {
        ziti_config cfg = {};
        cfg.controller_url = const_cast<char *>("https://localhost:1");
        REQUIRE(ziti_context_init(&ztx, &cfg) == ZITI_OK);
        ziti_set_app_ctx(ztx, &inst);
        inst.ztx = ztx;
    }
};

// a test_identity that the command layer knows, as a loaded identity, while it is in scope
struct registered_identity : test_identity {
    std::string identifier;

    explicit registered_identity(const char *id) : identifier(id) {
        set_ziti_instance(identifier.c_str(), &inst);
    }

    ~registered_identity() {
        remove_ziti_instance(identifier.c_str());
    }
};

#endif //ZITI_TUNNEL_SDK_TEST_TUNNELER_H
