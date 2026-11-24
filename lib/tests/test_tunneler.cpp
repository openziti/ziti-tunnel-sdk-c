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

#include "test_tunneler.h"

static int mock_add_route(netif_handle tun, const char *dest) {
    return 0;
}

static int mock_delete_route(netif_handle tun, const char *dest) {
    return 0;
}

int test_route_commits = 0;

static int mock_commit_routes(netif_handle tun, uv_loop_t *loop) {
    test_route_commits++;
    return 0;
}

static void ignore_event(const base_event *ev) {
}

tunneler_context test_tunneler() {
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
        mock_netif.commit_routes = mock_commit_routes;
        tnlr = ziti_tunneler_init(&tnlr_opts, uv_default_loop());
    }
    // every time: other tests give the command layer a tunneler of their own
    ziti_tunnel_init_cmd(uv_default_loop(), tnlr, ignore_event);
    return tnlr;
}
