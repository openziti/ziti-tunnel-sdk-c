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

//
// Exercises the pure trigger-matching/action/cost-precedence decision logic in
// health_checks.c via health_checks_internal.h -- no live libuv loop, uv_connection, or
// ziti overlay is needed for any of this.
//

#include "catch2/catch.hpp"
#include "../health_checks_internal.h"

TEST_CASE("health check: parse_trigger/parse_action", "[health]") {
    CHECK(parse_trigger("fail") == HC_TRIGGER_FAIL);
    CHECK(parse_trigger("pass") == HC_TRIGGER_PASS);
    CHECK(parse_trigger("change") == HC_TRIGGER_CHANGE);
    CHECK(parse_trigger("bogus") == HC_TRIGGER_UNKNOWN);
    CHECK(parse_trigger(nullptr) == HC_TRIGGER_UNKNOWN);

    long amount = -1;
    CHECK(parse_action("mark healthy", &amount) == HC_ACTION_MARK_HEALTHY);
    CHECK(amount == 0);
    CHECK(parse_action("mark unhealthy", &amount) == HC_ACTION_MARK_UNHEALTHY);
    CHECK(parse_action("send event", &amount) == HC_ACTION_SEND_EVENT);

    CHECK(parse_action("increase cost 50", &amount) == HC_ACTION_INCREASE_COST);
    CHECK(amount == 50);
    CHECK(parse_action("decrease cost 250", &amount) == HC_ACTION_DECREASE_COST);
    CHECK(amount == 250);

    CHECK(parse_action("bogus", &amount) == HC_ACTION_UNKNOWN);
}

static health_action_t make_action(health_trigger_kind_t trigger, health_action_kind_t kind,
                                    const int64_t *consecutive_events = nullptr,
                                    const int64_t *duration_ns = nullptr) {
    health_action_t a = {};
    a.trigger = trigger;
    a.kind = kind;
    a.consecutive_events = consecutive_events;
    a.duration_ns = duration_ns;
    return a;
}

TEST_CASE("health check: trigger matching, no consecutiveEvents/duration", "[health]") {
    SECTION("fail trigger matches only on failure") {
        health_action_t a = make_action(HC_TRIGGER_FAIL, HC_ACTION_MARK_UNHEALTHY);
        action_update_bookkeeping(&a, false, 1000);
        CHECK(action_matches(&a, false, 1, false, 0, 1000));
        action_update_bookkeeping(&a, true, 2000);
        CHECK_FALSE(action_matches(&a, true, 0, false, 0, 2000));
    }

    SECTION("pass trigger matches only on pass") {
        health_action_t a = make_action(HC_TRIGGER_PASS, HC_ACTION_MARK_HEALTHY);
        action_update_bookkeeping(&a, true, 1000);
        CHECK(action_matches(&a, true, 0, false, 0, 1000));
        action_update_bookkeeping(&a, false, 2000);
        CHECK_FALSE(action_matches(&a, false, 1, true, 2000, 2000));
    }

    SECTION("change trigger matches on the first pass after failing, and the first failure after passing") {
        health_action_t a = make_action(HC_TRIGGER_CHANGE, HC_ACTION_SEND_EVENT);

        // first result ever (a pass): consecutive_passes becomes 1 -> matches
        action_update_bookkeeping(&a, true, 1000);
        CHECK(action_matches(&a, true, 0, false, 0, 1000));

        // second consecutive pass: consecutive_passes becomes 2, contiguous_failures
        // still 0 -> does not match
        action_update_bookkeeping(&a, true, 1100);
        CHECK_FALSE(action_matches(&a, true, 0, false, 0, 1100));

        // first failure after passing: contiguous_failures becomes 1 -> matches
        action_update_bookkeeping(&a, false, 1200);
        CHECK(action_matches(&a, false, 1, true, 1200, 1200));

        // second consecutive failure: contiguous_failures becomes 2 -> does not match
        action_update_bookkeeping(&a, false, 1300);
        CHECK_FALSE(action_matches(&a, false, 2, true, 1200, 1300));
    }

    SECTION("unknown trigger or action never matches") {
        health_action_t a = make_action(HC_TRIGGER_UNKNOWN, HC_ACTION_MARK_UNHEALTHY);
        action_update_bookkeeping(&a, false, 1000);
        CHECK_FALSE(action_matches(&a, false, 1, true, 1000, 1000));

        health_action_t b = make_action(HC_TRIGGER_FAIL, HC_ACTION_UNKNOWN);
        action_update_bookkeeping(&b, false, 1000);
        CHECK_FALSE(action_matches(&b, false, 1, true, 1000, 1000));
    }
}

TEST_CASE("health check: consecutiveEvents gates the match", "[health]") {
    int64_t need = 3;
    health_action_t a = make_action(HC_TRIGGER_FAIL, HC_ACTION_MARK_UNHEALTHY, &need);

    uint64_t now = 0;
    for (int i = 1; i < 3; i++) {
        now += 1000;
        action_update_bookkeeping(&a, false, now);
        CHECK_FALSE(action_matches(&a, false, i, true, 1000, now));
    }
    now += 1000;
    action_update_bookkeeping(&a, false, now);
    CHECK(action_matches(&a, false, 3, true, 1000, now));

    // a pass resets the failure streak, so a subsequent short failure streak doesn't match
    action_update_bookkeeping(&a, true, now + 1000);
    action_update_bookkeeping(&a, false, now + 2000);
    CHECK_FALSE(action_matches(&a, false, 1, true, now + 2000, now + 2000));
}

TEST_CASE("health check: duration gates the match", "[health]") {
    int64_t need_ms = 1000; // stored as nanoseconds-equivalent via DURATION_MILLISECONDS
    int64_t duration_ns = need_ms * 1000000LL; // MILLISECOND-scale conversion mirrors ziti's duration type

    SECTION("passing duration") {
        health_action_t a = make_action(HC_TRIGGER_PASS, HC_ACTION_MARK_HEALTHY, nullptr, &duration_ns);
        action_update_bookkeeping(&a, true, 1000); // passing_since_ms = 1000
        CHECK_FALSE(action_matches(&a, true, 0, false, 0, 1500)); // only 500ms elapsed
        action_update_bookkeeping(&a, true, 2100);
        CHECK(action_matches(&a, true, 0, false, 0, 2100)); // 1100ms since passing_since
    }

    SECTION("failing duration") {
        health_action_t a = make_action(HC_TRIGGER_FAIL, HC_ACTION_MARK_UNHEALTHY, nullptr, &duration_ns);
        action_update_bookkeeping(&a, false, 1000);
        CHECK_FALSE(action_matches(&a, false, 1, true, 1000, 1500)); // only 500ms since first failure
        action_update_bookkeeping(&a, false, 2100);
        CHECK(action_matches(&a, false, 2, true, 1000, 2100)); // 1100ms since first failure
    }
}

static struct health_checks_ctx_s make_hc(uint16_t baseline_cost, uint8_t baseline_precedence) {
    struct health_checks_ctx_s hc = {};
    hc.baseline_cost = baseline_cost;
    hc.baseline_precedence = baseline_precedence;
    hc.current_cost = hc.next_cost = baseline_cost;
    hc.current_precedence = hc.next_precedence = baseline_precedence;
    return hc;
}

TEST_CASE("health check: apply_action_effect cost/precedence semantics", "[health]") {
    SECTION("mark unhealthy sets precedence to failed") {
        auto hc = make_hc(0, PRECEDENCE.DEFAULT);
        health_action_t a = make_action(HC_TRIGGER_FAIL, HC_ACTION_MARK_UNHEALTHY);
        a.amount = 0;
        bool send_event = false;
        apply_action_effect(&hc, &a, &send_event);
        CHECK(hc.next_precedence == PRECEDENCE.FAILED);
        CHECK_FALSE(send_event);
        CHECK(health_state_changed(&hc));
    }

    SECTION("mark healthy restores the baseline precedence, not a hardcoded default") {
        auto hc = make_hc(0, PRECEDENCE.REQUIRED);
        hc.current_precedence = hc.next_precedence = PRECEDENCE.FAILED;
        health_action_t a = make_action(HC_TRIGGER_PASS, HC_ACTION_MARK_HEALTHY);
        bool send_event = false;
        apply_action_effect(&hc, &a, &send_event);
        CHECK(hc.next_precedence == PRECEDENCE.REQUIRED);
    }

    SECTION("increase cost accumulates across repeated matches, clamped to UINT16_MAX") {
        auto hc = make_hc(100, PRECEDENCE.DEFAULT);
        health_action_t a = make_action(HC_TRIGGER_FAIL, HC_ACTION_INCREASE_COST);
        a.amount = 40000;
        bool send_event = false;

        apply_action_effect(&hc, &a, &send_event);
        CHECK(hc.next_cost == 40100);

        hc.current_cost = hc.next_cost; // simulate a successful terminator update in between
        apply_action_effect(&hc, &a, &send_event);
        CHECK(hc.next_cost == UINT16_MAX); // 40100 + 40000 overflows uint16_t, clamps
    }

    SECTION("increase cost is suppressed once the terminator is already marked failed") {
        auto hc = make_hc(100, PRECEDENCE.DEFAULT);
        hc.current_precedence = PRECEDENCE.FAILED; // as if a prior "mark unhealthy" already applied
        health_action_t a = make_action(HC_TRIGGER_FAIL, HC_ACTION_INCREASE_COST);
        a.amount = 500;
        bool send_event = false;
        apply_action_effect(&hc, &a, &send_event);
        CHECK(hc.next_cost == 100); // unchanged
    }

    SECTION("decrease cost floors at baseline, never below") {
        auto hc = make_hc(100, PRECEDENCE.DEFAULT);
        hc.current_cost = hc.next_cost = 250;
        health_action_t a = make_action(HC_TRIGGER_PASS, HC_ACTION_DECREASE_COST);
        a.amount = 1000; // far more than the distance back to baseline
        bool send_event = false;
        apply_action_effect(&hc, &a, &send_event);
        CHECK(hc.next_cost == 100); // floored at baseline, not negative/underflowed
    }

    SECTION("send event sets the flag and leaves cost/precedence untouched") {
        auto hc = make_hc(100, PRECEDENCE.DEFAULT);
        health_action_t a = make_action(HC_TRIGGER_CHANGE, HC_ACTION_SEND_EVENT);
        bool send_event = false;
        apply_action_effect(&hc, &a, &send_event);
        CHECK(send_event);
        CHECK_FALSE(health_state_changed(&hc));
    }
}

TEST_CASE("health check: two checks on one service compose into a single pending update", "[health]") {
    auto hc = make_hc(50, PRECEDENCE.DEFAULT);

    // check A: a port check that just failed and wants to increase cost
    health_action_t a_increase = make_action(HC_TRIGGER_FAIL, HC_ACTION_INCREASE_COST);
    a_increase.amount = 25;

    // check B: an http check that just failed and wants to mark the terminator unhealthy
    health_action_t b_mark_unhealthy = make_action(HC_TRIGGER_FAIL, HC_ACTION_MARK_UNHEALTHY);

    CHECK_FALSE(health_state_changed(&hc));

    bool send_event = false;
    apply_action_effect(&hc, &a_increase, &send_event);
    apply_action_effect(&hc, &b_mark_unhealthy, &send_event);

    // both effects landed on the same hc -- a single terminator update carries both
    CHECK(hc.next_cost == 75);
    CHECK(hc.next_precedence == PRECEDENCE.FAILED);
    CHECK(health_state_changed(&hc));
    CHECK_FALSE(send_event);
}

TEST_CASE("health check: no update is indicated when nothing changed", "[health]") {
    auto hc = make_hc(100, PRECEDENCE.REQUIRED);
    CHECK_FALSE(health_state_changed(&hc));

    // an action that doesn't match anything (e.g. a pass-trigger action while failing)
    // should never be invoked in practice, but even a no-op effect leaves state unchanged
    health_action_t a = make_action(HC_TRIGGER_PASS, HC_ACTION_MARK_HEALTHY);
    bool send_event = false;
    apply_action_effect(&hc, &a, &send_event); // mark healthy while already at baseline
    CHECK_FALSE(health_state_changed(&hc));
}
