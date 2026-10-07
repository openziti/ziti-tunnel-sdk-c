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
// Internal to the health-check engine. NOT part of the public API (see health_checks.h
// for that) -- exists so the pure trigger-matching/action/cost-precedence logic in
// health_checks.c can be exercised directly by unit tests, without a live libuv loop,
// uv_connection, or ziti overlay. health_checks.c is the only non-test consumer.
//

#ifndef ZITI_TUNNEL_SDK_C_HEALTH_CHECKS_INTERNAL_H
#define ZITI_TUNNEL_SDK_C_HEALTH_CHECKS_INTERNAL_H

#include <stdint.h>
#include <stdbool.h>

#include "ziti_hosting.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CHECK_PORT,
    CHECK_HTTP,
} check_type_t;

typedef enum {
    HC_TRIGGER_FAIL,
    HC_TRIGGER_PASS,
    HC_TRIGGER_CHANGE,
    HC_TRIGGER_UNKNOWN,
} health_trigger_kind_t;

typedef enum {
    HC_ACTION_MARK_HEALTHY,
    HC_ACTION_MARK_UNHEALTHY,
    HC_ACTION_SEND_EVENT,
    HC_ACTION_INCREASE_COST,
    HC_ACTION_DECREASE_COST,
    HC_ACTION_UNKNOWN,
} health_action_kind_t;

typedef struct health_action_s {
    health_trigger_kind_t trigger;
    health_action_kind_t kind;
    long amount; // for HC_ACTION_INCREASE_COST/HC_ACTION_DECREASE_COST

    const int64_t *consecutive_events; // borrowed from the parsed ziti_check_action; NULL if unset
    const int64_t *duration_ns;        // borrowed from the parsed ziti_check_action; NULL if unset

    // per-action matcher bookkeeping -- updated on every result, independent of whether
    // this action ends up matching. mirrors go's actionImpl.consectivePasses/passingSince.
    int64_t consecutive_passes;
    uint64_t passing_since_ms;
} health_action_t;

struct health_check_s {
    struct health_checks_ctx_s *hc;
    check_type_t type;
    const void *cfg; // ziti_port_check* or ziti_http_check*, borrowed from host_ctx->cfg

    char id[16]; // e.g. "port-0", "http-1" -- stable identifier for the IPC/status feed

    uint64_t interval_ms;
    long timeout_ms;
    int resolved_expect_status; // http only; defaulted to 200 once at setup

    uv_timer_t timer;

    // shared result bookkeeping, read by every action attached to this check
    bool is_healthy;
    int64_t contiguous_failures;
    bool has_time_of_first_failure;
    uint64_t time_of_first_failure_ms;
    char last_err[128]; // most recent failure reason; empty while passing

    health_action_t *actions;
    int action_count;

    bool attempt_in_flight;

    // teardown
    bool stopping;
    int pending_closes;
};

struct health_checks_ctx_s {
    struct hosted_service_ctx_s *host_ctx;

    // cached from host_ctx->tnlr_ctx->loop at start -- hc (and any in-flight http check
    // attempt referencing it) can outlive host_ctx during teardown; see finish_http_check().
    uv_loop_t *loop;

    uint16_t baseline_cost;
    uint8_t  baseline_precedence;
    uint16_t current_cost;
    uint8_t  current_precedence;
    uint16_t next_cost;
    uint8_t  next_precedence;

    struct health_check_s **checks;
    int check_count;

    bool stopping;
    int pending_closes;
};

// ---- pure decision logic, exercised directly by unit tests ----

// rounds ms to the nearest TIME_CLAMP_MS (100ms), matching go's roundToClosest/timeClamp
// -- keeps duration-trigger comparisons stable against small scheduling jitter.
uint64_t round_to_time_clamp(uint64_t ms);

health_trigger_kind_t parse_trigger(const char *s);

// parses an action string (e.g. "increase cost 50"); *amount_out receives the parsed
// amount for HC_ACTION_INCREASE_COST/HC_ACTION_DECREASE_COST, 0 otherwise.
health_action_kind_t parse_action(const char *s, long *amount_out);

// updates a's own consecutive_passes/passing_since_ms for this result. Must be called
// once per action, per result, BEFORE action_matches() -- mirrors go's actionImpl.Matches(),
// which updates this bookkeeping unconditionally before evaluating whether it matches.
void action_update_bookkeeping(health_action_t *a, bool passed, uint64_t now_ms);

// evaluates whether action a matches this result, given the check-level shared result
// state (contiguous_failures/has_time_of_first_failure/time_of_first_failure_ms) and a's
// own (already-updated) consecutive_passes/passing_since_ms.
bool action_matches(const health_action_t *a, bool passed,
                     int64_t contiguous_failures, bool has_time_of_first_failure,
                     uint64_t time_of_first_failure_ms, uint64_t now_ms);

// applies a matching action's effect to hc's next_cost/next_precedence, or sets
// *send_event_out for a "send event" action.
void apply_action_effect(struct health_checks_ctx_s *hc, const health_action_t *a, bool *send_event_out);

// true if hc's next_cost/next_precedence differ from current_cost/current_precedence --
// i.e. whether a terminator update needs to be sent.
bool health_state_changed(const struct health_checks_ctx_s *hc);

#ifdef __cplusplus
}
#endif

#endif //ZITI_TUNNEL_SDK_C_HEALTH_CHECKS_INTERNAL_H
