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

#include <cstdlib>

#include "catch2/catch.hpp"
#include "ziti/ziti_tunnel_cbs.h"

namespace {

// no ziti context: enough to feed events
struct state_instance {
    struct ziti_instance_s *inst = new_ziti_instance("identity-state-test");

    ~state_instance() {
        free(inst->identifier);
        free(inst);
    }
};

ziti_event_t context_event(int status) {
    ziti_event_t ev = {};
    ev.type = ZitiContextEvent;
    ev.ctx.ctrl_status = status;
    return ev;
}

ziti_event_t auth_event(int action) {
    ziti_event_t ev = {};
    ev.type = ZitiAuthEvent;
    ev.auth.action = static_cast<ziti_auth_action>(action);
    return ev;
}

void feed(struct ziti_instance_s *inst, const ziti_event_t &ev) {
    ziti_instance_apply_event(inst, &ev);
}

void check_state(const struct ziti_instance_s *inst, tnl_auth_state s, tnl_auth_needs n, tnl_mfa_enrolled m) {
    CHECK(inst->auth_state == s);
    CHECK(inst->auth_needs == n);
    CHECK(inst->mfa_enrolled == m);
}

} // namespace

TEST_CASE("a new instance has seen nothing", "[identity-state]") {
    state_instance s;
    check_state(s.inst, tnl_auth_state_Unknown, tnl_auth_needs_Unknown, tnl_mfa_enrolled_Unknown);
}

TEST_CASE("context events set the state", "[identity-state]") {
    state_instance s;
    SECTION("ok") {
        feed(s.inst, context_event(ZITI_OK));
        check_state(s.inst, tnl_auth_state_authenticated, tnl_auth_needs_none, tnl_mfa_enrolled_Unknown);
    }
    SECTION("partial") {
        feed(s.inst, context_event(ZITI_PARTIALLY_AUTHENTICATED));
        check_state(s.inst, tnl_auth_state_partial, tnl_auth_needs_Unknown, tnl_mfa_enrolled_Unknown);
    }
    SECTION("disabled") {
        feed(s.inst, context_event(ZITI_DISABLED));
        check_state(s.inst, tnl_auth_state_disabled, tnl_auth_needs_none, tnl_mfa_enrolled_Unknown);
    }
    SECTION("unavailable") {
        feed(s.inst, context_event(ZITI_CONTROLLER_UNAVAILABLE));
        check_state(s.inst, tnl_auth_state_failed, tnl_auth_needs_none, tnl_mfa_enrolled_Unknown);
    }
    SECTION("auth failed") {
        feed(s.inst, context_event(ZITI_AUTHENTICATION_FAILED));
        check_state(s.inst, tnl_auth_state_failed, tnl_auth_needs_none, tnl_mfa_enrolled_Unknown);
    }
}

TEST_CASE("auth events say what the login waits for", "[identity-state]") {
    state_instance s;
    SECTION("enroll totp") {
        feed(s.inst, auth_event(ziti_auth_enroll_totp));
        check_state(s.inst, tnl_auth_state_partial, tnl_auth_needs_totp_enroll, tnl_mfa_enrolled_not_enrolled);
    }
    SECTION("prompt totp") {
        feed(s.inst, auth_event(ziti_auth_prompt_totp));
        check_state(s.inst, tnl_auth_state_partial, tnl_auth_needs_totp_code, tnl_mfa_enrolled_enrolled);
    }
    SECTION("select external") {
        feed(s.inst, auth_event(ziti_auth_select_external));
        check_state(s.inst, tnl_auth_state_partial, tnl_auth_needs_ext_jwt, tnl_mfa_enrolled_Unknown);
    }
    SECTION("login external") {
        feed(s.inst, auth_event(ziti_auth_login_external));
        check_state(s.inst, tnl_auth_state_partial, tnl_auth_needs_ext_jwt, tnl_mfa_enrolled_Unknown);
    }
    SECTION("prompt pin") {
        feed(s.inst, auth_event(ziti_auth_prompt_pin));
        check_state(s.inst, tnl_auth_state_partial, tnl_auth_needs_key_pin, tnl_mfa_enrolled_Unknown);
    }
    SECTION("success") {
        feed(s.inst, auth_event(ziti_auth_success));
        check_state(s.inst, tnl_auth_state_authenticated, tnl_auth_needs_none, tnl_mfa_enrolled_Unknown);
    }
    SECTION("cannot continue") {
        feed(s.inst, auth_event(ziti_auth_cannot_continue));
        check_state(s.inst, tnl_auth_state_failed, tnl_auth_needs_none, tnl_mfa_enrolled_Unknown);
    }
}

// the ContextEvent for a partial login comes first, the auth event that explains it right after, and a context that
// has not authenticated has no identity data to tell the SDK about TOTP: the prompt is all there is
TEST_CASE("restart at the TOTP prompt", "[identity-state]") {
    state_instance s;
    feed(s.inst, context_event(ZITI_PARTIALLY_AUTHENTICATED));
    feed(s.inst, auth_event(ziti_auth_prompt_totp));
    check_state(s.inst, tnl_auth_state_partial, tnl_auth_needs_totp_code, tnl_mfa_enrolled_enrolled);

    ziti_instance_sync_mfa_enrolled(s.inst); // no ztx: must not reset it
    feed(s.inst, auth_event(ziti_auth_success));
    check_state(s.inst, tnl_auth_state_authenticated, tnl_auth_needs_none, tnl_mfa_enrolled_enrolled);
}

TEST_CASE("partial login re-delivered or re-entered", "[identity-state]") {
    state_instance s;
    SECTION("already partial keeps what it needs") {
        feed(s.inst, auth_event(ziti_auth_prompt_totp));
        feed(s.inst, context_event(ZITI_PARTIALLY_AUTHENTICATED));
        check_state(s.inst, tnl_auth_state_partial, tnl_auth_needs_totp_code, tnl_mfa_enrolled_enrolled);
    }
    SECTION("from authenticated forgets the last login's need") {
        feed(s.inst, auth_event(ziti_auth_prompt_totp));
        feed(s.inst, context_event(ZITI_OK));
        feed(s.inst, context_event(ZITI_PARTIALLY_AUTHENTICATED));
        check_state(s.inst, tnl_auth_state_partial, tnl_auth_needs_Unknown, tnl_mfa_enrolled_enrolled);
    }
}

TEST_CASE("input that changes nothing", "[identity-state]") {
    state_instance s;
    feed(s.inst, auth_event(ziti_auth_prompt_totp));
    SECTION("unknown action") {
        feed(s.inst, auth_event(99));
    }
    SECTION("other event type") {
        ziti_event_t ev = {};
        ev.type = ZitiServiceEvent;
        feed(s.inst, ev);
    }
    SECTION("null instance") {
        ziti_event_t ev = context_event(ZITI_OK);
        ziti_instance_apply_event(nullptr, &ev);
    }
    SECTION("null event") {
        ziti_instance_apply_event(s.inst, nullptr);
    }
    check_state(s.inst, tnl_auth_state_partial, tnl_auth_needs_totp_code, tnl_mfa_enrolled_enrolled);
}

TEST_CASE("sync keeps what it cannot improve", "[identity-state]") {
    // a context that never reached a controller has no identity data
    ziti_config cfg = {};
    cfg.controller_url = const_cast<char *>("https://localhost:1");
    ziti_context ztx = nullptr;
    REQUIRE(ziti_context_init(&ztx, &cfg) == ZITI_OK);
    REQUIRE(ziti_get_identity(ztx) == nullptr);

    state_instance s;
    s.inst->ztx = ztx;
    ziti_instance_sync_mfa_enrolled(s.inst);
    CHECK(s.inst->mfa_enrolled == tnl_mfa_enrolled_Unknown);

    s.inst->mfa_enrolled = tnl_mfa_enrolled_enrolled;
    ziti_instance_sync_mfa_enrolled(s.inst);
    CHECK(s.inst->mfa_enrolled == tnl_mfa_enrolled_enrolled);

    s.inst->mfa_enrolled = tnl_mfa_enrolled_not_enrolled;
    ziti_instance_sync_mfa_enrolled(s.inst);
    CHECK(s.inst->mfa_enrolled == tnl_mfa_enrolled_not_enrolled);
}

TEST_CASE("disabling and enabling an identity", "[identity-state]") {
    state_instance s;
    s.inst->mfa_enrolled = tnl_mfa_enrolled_enrolled;
    feed(s.inst, context_event(ZITI_OK));

    ziti_instance_set_enabled(s.inst, false);
    check_state(s.inst, tnl_auth_state_disabled, tnl_auth_needs_none, tnl_mfa_enrolled_enrolled);

    // nothing has been seen since the restart, but what is known of MFA does not depend on it
    ziti_instance_set_enabled(s.inst, true);
    check_state(s.inst, tnl_auth_state_Unknown, tnl_auth_needs_Unknown, tnl_mfa_enrolled_enrolled);
}

// the SDK sends no event for a context that starts disabled
TEST_CASE("an identity loaded disabled starts disabled", "[identity-state]") {
    ziti_config cfg = {};
    cfg.controller_url = const_cast<char *>("https://localhost:1");
    ziti_options opts = {};
    state_instance off, on;

    opts.disabled = true;
    REQUIRE(init_ziti_instance(off.inst, &cfg, &opts) == ZITI_OK);
    CHECK(off.inst->auth_state == tnl_auth_state_disabled);

    opts.disabled = false;
    REQUIRE(init_ziti_instance(on.inst, &cfg, &opts) == ZITI_OK);
    CHECK(on.inst->auth_state == tnl_auth_state_Unknown);
}

// turning on an identity that is on starts nothing in the SDK, so no event follows to restore what is known
TEST_CASE("enabling an identity that is enabled changes nothing", "[identity-state]") {
    state_instance s;
    SECTION("authenticated") {
        feed(s.inst, context_event(ZITI_OK));
        ziti_instance_set_enabled(s.inst, true);
        check_state(s.inst, tnl_auth_state_authenticated, tnl_auth_needs_none, tnl_mfa_enrolled_Unknown);
    }
    SECTION("waiting at the TOTP prompt") {
        feed(s.inst, context_event(ZITI_PARTIALLY_AUTHENTICATED));
        feed(s.inst, auth_event(ziti_auth_prompt_totp));
        ziti_instance_set_enabled(s.inst, true);
        check_state(s.inst, tnl_auth_state_partial, tnl_auth_needs_totp_code, tnl_mfa_enrolled_enrolled);
    }
}

// the SDK sends the list of controllers in a context event too, with no status of its own, which reads as ZITI_OK
TEST_CASE("a controller list says nothing about authentication", "[identity-state]") {
    struct ctrl_detail_s detail = {};
    ziti_event_t list_change = context_event(ZITI_OK);
    list_change.ctx.ctrl_count = 1;
    list_change.ctx.ctrl_details = &detail;

    state_instance s;
    SECTION("at the TOTP prompt") {
        feed(s.inst, context_event(ZITI_PARTIALLY_AUTHENTICATED));
        feed(s.inst, auth_event(ziti_auth_prompt_totp));
        feed(s.inst, list_change);
        check_state(s.inst, tnl_auth_state_partial, tnl_auth_needs_totp_code, tnl_mfa_enrolled_enrolled);
    }
    SECTION("after a failure") {
        feed(s.inst, context_event(ZITI_AUTHENTICATION_FAILED));
        feed(s.inst, list_change);
        check_state(s.inst, tnl_auth_state_failed, tnl_auth_needs_none, tnl_mfa_enrolled_Unknown);
    }
    SECTION("before anything") {
        feed(s.inst, list_change);
        check_state(s.inst, tnl_auth_state_Unknown, tnl_auth_needs_Unknown, tnl_mfa_enrolled_Unknown);
    }
}
