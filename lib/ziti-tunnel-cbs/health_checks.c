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
// host.v1 portChecks/httpChecks: probes a hosted service's backend on an interval and,
// on transitions, pushes cost/precedence updates via ziti_update_terminator() so the
// overlay steers traffic away from (or back to) a degraded terminator. Mirrors the
// design of ziti/tunnel/health in the Go tunneler (checks.go, health.go) -- see that
// package for the reference behavior this file ports.
//
// The pure trigger-matching/action/cost-precedence decision logic lives in
// health_checks_internal.h so it can be unit tested without a live libuv loop; this file
// is the uv/tlsuv-driven scheduling and I/O around that logic.
//

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <ziti/ziti_log.h>

#include "health_checks_internal.h"
#include "health_checks.h"

#if _WIN32
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#endif

#define TIME_CLAMP_MS 100UL
#define MIN_CHECK_INTERVAL_MS 1000UL
#define MIN_CHECK_TIMEOUT_MS 250UL
#define HTTP_CHECK_BODY_CAP 4096

struct port_check_attempt_s {
    struct health_check_s *check;
    uv_getaddrinfo_t resolve_req;
    uv_tcp_t sock;
    uv_timer_t timeout_timer;
    uv_connect_t connect_req;
    bool completed;
    bool passed;
    char err_buf[128];
    int pending_handle_closes;
};

struct http_check_attempt_s {
    struct health_check_s *check;
    tlsuv_http_t client;
    bool finished;
    bool passed;
    char err_buf[128];
    int status_code;
    char body_buf[HTTP_CHECK_BODY_CAP];
    size_t body_len;
};

static void on_check_timer(uv_timer_t *t);
static void on_check_timer_closed(uv_handle_t *h);
static void check_teardown_progress(struct health_check_s *check);
static void on_check_attempt_complete(struct health_check_s *check, bool passed, const char *err);
static void start_port_check(struct health_check_s *check);
static void start_http_check(struct health_check_s *check);

/* ---------------------------------------------------------------------- */
/* pure decision logic (declared in health_checks_internal.h)              */
/* ---------------------------------------------------------------------- */

uint64_t round_to_time_clamp(uint64_t ms) {
    uint64_t rem = ms % TIME_CLAMP_MS;
    if (rem >= TIME_CLAMP_MS / 2) {
        return ms - rem + TIME_CLAMP_MS;
    }
    return ms - rem;
}

health_trigger_kind_t parse_trigger(const char *s) {
    if (s == NULL) return HC_TRIGGER_UNKNOWN;
    if (strcmp(s, "fail") == 0) return HC_TRIGGER_FAIL;
    if (strcmp(s, "pass") == 0) return HC_TRIGGER_PASS;
    if (strcmp(s, "change") == 0) return HC_TRIGGER_CHANGE;
    return HC_TRIGGER_UNKNOWN;
}

health_action_kind_t parse_action(const char *s, long *amount_out) {
    *amount_out = 0;
    if (s == NULL) return HC_ACTION_UNKNOWN;
    if (strcmp(s, "mark healthy") == 0) return HC_ACTION_MARK_HEALTHY;
    if (strcmp(s, "mark unhealthy") == 0) return HC_ACTION_MARK_UNHEALTHY;
    if (strcmp(s, "send event") == 0) return HC_ACTION_SEND_EVENT;
    if (strncmp(s, "increase cost ", 14) == 0) {
        *amount_out = strtol(s + 14, NULL, 10);
        return HC_ACTION_INCREASE_COST;
    }
    if (strncmp(s, "decrease cost ", 14) == 0) {
        *amount_out = strtol(s + 14, NULL, 10);
        return HC_ACTION_DECREASE_COST;
    }
    return HC_ACTION_UNKNOWN;
}

void action_update_bookkeeping(health_action_t *a, bool passed, uint64_t now_ms) {
    if (passed) {
        if (a->consecutive_passes == 0) a->passing_since_ms = now_ms;
        a->consecutive_passes++;
    } else {
        a->consecutive_passes = 0;
    }
}

bool action_matches(const health_action_t *a, bool passed,
                     int64_t contiguous_failures, bool has_time_of_first_failure,
                     uint64_t time_of_first_failure_ms, uint64_t now_ms) {
    if (a->trigger == HC_TRIGGER_UNKNOWN || a->kind == HC_ACTION_UNKNOWN) return false;

    if (a->trigger == HC_TRIGGER_FAIL && passed) return false;
    if (a->trigger == HC_TRIGGER_PASS && !passed) return false;
    if (a->trigger == HC_TRIGGER_CHANGE) {
        if (a->consecutive_passes != 1 && contiguous_failures != 1) return false;
    }

    if (a->consecutive_events != NULL) {
        int64_t need = *a->consecutive_events;
        if (passed && a->consecutive_passes < need) return false;
        if (!passed && contiguous_failures < need) return false;
    }

    if (a->duration_ns != NULL) {
        uint64_t need_ms = (uint64_t) DURATION_MILLISECONDS(*a->duration_ns);
        if (passed && (now_ms - a->passing_since_ms) < need_ms) return false;
        if (!passed && has_time_of_first_failure && (now_ms - time_of_first_failure_ms) < need_ms) {
            return false;
        }
    }

    return true;
}

void apply_action_effect(struct health_checks_ctx_s *hc, const health_action_t *a, bool *send_event_out) {
    switch (a->kind) {
        case HC_ACTION_MARK_UNHEALTHY:
            hc->next_precedence = PRECEDENCE.FAILED;
            break;
        case HC_ACTION_MARK_HEALTHY:
            hc->next_precedence = hc->baseline_precedence;
            break;
        case HC_ACTION_SEND_EVENT:
            *send_event_out = true;
            break;
        case HC_ACTION_INCREASE_COST:
            // don't keep raising cost once the terminator is already marked failed --
            // matches go's guard on state.currentPrecedence in checks.go.
            if (hc->current_precedence != PRECEDENCE.FAILED) {
                uint32_t v = (uint32_t) hc->next_cost + (uint32_t) a->amount;
                hc->next_cost = v > UINT16_MAX ? UINT16_MAX : (uint16_t) v;
            }
            break;
        case HC_ACTION_DECREASE_COST: {
            int32_t v = (int32_t) hc->next_cost - (int32_t) a->amount;
            hc->next_cost = v < (int32_t) hc->baseline_cost ? hc->baseline_cost : (uint16_t) v;
            break;
        }
        default:
            break;
    }
}

bool health_state_changed(const struct health_checks_ctx_s *hc) {
    return hc->next_cost != hc->current_cost || hc->next_precedence != hc->current_precedence;
}

/* ---------------------------------------------------------------------- */
/* config helpers                                                          */
/* ---------------------------------------------------------------------- */

static uint64_t clamp_interval_ms(int64_t interval_ns, const char *service_name) {
    int64_t ms = interval_ns > 0 ? DURATION_MILLISECONDS(interval_ns) : 0;
    if (ms < (int64_t) MIN_CHECK_INTERVAL_MS) {
        ZITI_LOG(WARN, "hosted_service[%s] health check interval invalid or too small, using %lums minimum",
                 service_name, MIN_CHECK_INTERVAL_MS);
        return MIN_CHECK_INTERVAL_MS;
    }
    return (uint64_t) ms;
}

static long clamp_timeout_ms(int64_t timeout_ns) {
    int64_t ms = timeout_ns > 0 ? DURATION_MILLISECONDS(timeout_ns) : 0;
    if (ms < (int64_t) MIN_CHECK_TIMEOUT_MS) {
        return (long) MIN_CHECK_TIMEOUT_MS;
    }
    return (long) ms;
}

static health_action_t *build_actions(ziti_check_action_array actions, int *count_out) {
    int n = 0;
    if (actions != NULL) {
        while (actions[n] != NULL) n++;
    }
    *count_out = n;
    if (n == 0) return NULL;

    health_action_t *out = calloc((size_t) n, sizeof(health_action_t));
    for (int i = 0; i < n; i++) {
        ziti_check_action *a = actions[i];
        out[i].trigger = parse_trigger(a->trigger);
        out[i].kind = parse_action(a->action, &out[i].amount);
        out[i].consecutive_events = a->consecutive_events;
        out[i].duration_ns = a->duration;
        if (out[i].trigger == HC_TRIGGER_UNKNOWN || out[i].kind == HC_ACTION_UNKNOWN) {
            ZITI_LOG(WARN, "unsupported health check action trigger[%s] action[%s]; it will never match",
                     a->trigger ? a->trigger : "", a->action ? a->action : "");
        }
    }
    return out;
}

static struct health_check_s *build_check(struct health_checks_ctx_s *hc, check_type_t type, const void *cfg, int idx) {
    struct health_check_s *check = calloc(1, sizeof(*check));
    check->hc = hc;
    check->type = type;
    check->cfg = cfg;
    check->is_healthy = true; // assume passing until the first result arrives, matching Go's InitiallyPassing(true)
    snprintf(check->id, sizeof(check->id), "%s-%d", type == CHECK_PORT ? "port" : "http", idx);

    if (type == CHECK_PORT) {
        const ziti_port_check *pc = cfg;
        check->interval_ms = clamp_interval_ms(pc->interval, hc->host_ctx->service_name);
        check->timeout_ms = clamp_timeout_ms(pc->timeout);
        check->actions = build_actions(pc->actions, &check->action_count);
    } else {
        const ziti_http_check *hcfg = cfg;
        check->interval_ms = clamp_interval_ms(hcfg->interval, hc->host_ctx->service_name);
        check->timeout_ms = clamp_timeout_ms(hcfg->timeout);
        check->resolved_expect_status = hcfg->expect_status > 0 ? (int) hcfg->expect_status : 200;
        check->actions = build_actions(hcfg->actions, &check->action_count);
    }

    uv_loop_t *loop = hc->host_ctx->tnlr_ctx->loop;
    uv_timer_init(loop, &check->timer);
    check->timer.data = check;
    // fire once right away for prompt feedback on startup, then on the configured interval
    uv_timer_start(&check->timer, on_check_timer, 0, check->interval_ms);
    return check;
}

/* ---------------------------------------------------------------------- */
/* scheduling                                                              */
/* ---------------------------------------------------------------------- */

static void on_check_timer(uv_timer_t *t) {
    struct health_check_s *check = t->data;
    if (check->attempt_in_flight) {
        ZITI_LOG(DEBUG, "hosted_service[%s] health check still in flight, skipping this interval",
                 check->hc->host_ctx->service_name);
        return;
    }
    check->attempt_in_flight = true;
    if (check->type == CHECK_PORT) {
        start_port_check(check);
    } else {
        start_http_check(check);
    }
}

// Snapshots hc's current per-check state and the current effective cost/precedence into
// a health_status_event and delivers it via ziti_tunnel_send_event(). Called only when
// something actually changed (a check's own pass/fail transitioned, or a committed
// cost/precedence update happened) -- never on every probe interval.
static void emit_health_status_event(struct health_checks_ctx_s *hc) {
    struct hosted_service_ctx_s *host_ctx = hc->host_ctx;
    struct ziti_instance_s *instance = ziti_app_ctx((ziti_context) host_ctx->ziti_ctx);
    if (instance == NULL) return;

    const char *precedence_str = hc->current_precedence == PRECEDENCE.REQUIRED ? "required"
                                : hc->current_precedence == PRECEDENCE.FAILED ? "failed"
                                : "default";

    health_status_event ev = {0};
    ev.event_type = TunnelEvents.HealthStatusEvent;
    ev.identifier = instance->identifier;
    ev.service_name = host_ctx->service_name;
    ev.effective_cost = hc->current_cost;
    ev.effective_precedence = (model_string) precedence_str;

    health_check_result **checks = calloc((size_t) hc->check_count + 1, sizeof(health_check_result *));
    for (int i = 0; i < hc->check_count; i++) {
        struct health_check_s *c = hc->checks[i];
        health_check_result *r = calloc(1, sizeof(*r));
        r->id = strdup(c->id);
        r->check_type = strdup(c->type == CHECK_PORT ? "port" : "http");
        r->is_passing = c->is_healthy;
        r->consecutive_failures = c->contiguous_failures;
        if (!c->is_healthy && c->last_err[0]) {
            r->error = strdup(c->last_err);
        }
        checks[i] = r;
    }
    ev.checks = checks;

    ziti_tunnel_send_event((const base_event *) &ev);

    for (int i = 0; i < hc->check_count; i++) {
        free_health_check_result(checks[i]);
        free(checks[i]);
    }
    free(checks);
}

static void record_check_result(struct health_check_s *check, bool passed, const char *err) {
    struct health_checks_ctx_s *hc = check->hc;
    struct hosted_service_ctx_s *host_ctx = hc->host_ctx;
    uint64_t now_ms = round_to_time_clamp((uint64_t) uv_now(host_ctx->tnlr_ctx->loop));

    if (passed) {
        ZITI_LOG(DEBUG, "hosted_service[%s] health check passed", host_ctx->service_name);
    } else {
        ZITI_LOG(WARN, "hosted_service[%s] health check failed: %s",
                 host_ctx->service_name, err ? err : "unknown error");
    }

    bool was_healthy = check->is_healthy;
    uint16_t cost_before = hc->current_cost;
    uint8_t precedence_before = hc->current_precedence;

    if (passed) {
        check->contiguous_failures = 0;
        check->has_time_of_first_failure = false;
        check->last_err[0] = 0;
    } else {
        if (check->contiguous_failures == 0) {
            check->has_time_of_first_failure = true;
            check->time_of_first_failure_ms = now_ms;
        }
        check->contiguous_failures++;
        snprintf(check->last_err, sizeof(check->last_err), "%s", err ? err : "unknown error");
    }
    check->is_healthy = passed;

    bool send_event = false;
    for (int i = 0; i < check->action_count; i++) {
        health_action_t *a = &check->actions[i];

        // per-action bookkeeping updates unconditionally, before trigger matching --
        // mirrors go's actionImpl.Matches(), which updates its own consecutivePasses/
        // passingSince before evaluating whether this action actually matches.
        action_update_bookkeeping(a, passed, now_ms);

        if (!action_matches(a, passed, check->contiguous_failures, check->has_time_of_first_failure,
                             check->time_of_first_failure_ms, now_ms)) {
            continue;
        }

        apply_action_effect(hc, a, &send_event);
    }

    if (send_event) {
        if (host_ctx->serv != NULL) {
            int rc = ziti_send_health_event(host_ctx->serv, passed);
            if (rc != ZITI_OK) {
                ZITI_LOG(WARN, "hosted_service[%s] failed to send health event: %s",
                         host_ctx->service_name, ziti_errorstr(rc));
            }
        }
    }

    if (health_state_changed(hc)) {
        if (host_ctx->serv == NULL) {
            ZITI_LOG(WARN,
                     "hosted_service[%s] health check wants to update cost/precedence but service is not bound yet",
                     host_ctx->service_name);
        } else {
            bool cost_changed = hc->next_cost != hc->current_cost;
            bool precedence_changed = hc->next_precedence != hc->current_precedence;
            const uint16_t *cost_arg = cost_changed ? &hc->next_cost : NULL;
            const uint8_t *precedence_arg = precedence_changed ? &hc->next_precedence : NULL;

            int rc = ziti_update_terminator(host_ctx->serv, cost_arg, precedence_arg);
            if (rc == ZITI_OK) {
                ZITI_LOG(INFO, "hosted_service[%s] health check updated terminator cost[%u -> %u] precedence[%u -> %u]",
                         host_ctx->service_name, hc->current_cost, hc->next_cost, hc->current_precedence,
                         hc->next_precedence);
                hc->current_cost = hc->next_cost;
                hc->current_precedence = hc->next_precedence;
            } else {
                ZITI_LOG(WARN, "hosted_service[%s] failed to update terminator cost/precedence: %s",
                         host_ctx->service_name, ziti_errorstr(rc));
                // leave next_* as-is: the next result that changes anything will retry
                // with an equivalent delta, and a persistent failure-triggered action
                // (e.g. "increase cost") will simply keep nudging further on each
                // subsequent failed check.
            }
        }
    }

    bool committed_change = hc->current_cost != cost_before || hc->current_precedence != precedence_before;
    if (check->is_healthy != was_healthy || committed_change) {
        emit_health_status_event(hc);
    }
}

static void on_check_attempt_complete(struct health_check_s *check, bool passed, const char *err) {
    check->attempt_in_flight = false;
    if (check->stopping) {
        check_teardown_progress(check);
        return;
    }
    record_check_result(check, passed, err);
}

/* ---------------------------------------------------------------------- */
/* port checks                                                             */
/* ---------------------------------------------------------------------- */

// splits "host:port" (or "[ipv6]:port") into separately NUL-terminated host/port
// buffers. minimal bracket support for IPv6 literals; does not attempt full RFC 3986
// validation -- matches the level of effort a fixed health-check address warrants.
static bool split_host_port(const char *address, char *host, size_t host_len, char *port, size_t port_len) {
    const char *colon;
    if (address[0] == '[') {
        const char *close = strchr(address, ']');
        if (close == NULL || close[1] != ':') return false;
        size_t hlen = (size_t) (close - address - 1);
        if (hlen == 0 || hlen >= host_len) return false;
        memcpy(host, address + 1, hlen);
        host[hlen] = 0;
        colon = close + 1;
    } else {
        colon = strrchr(address, ':');
        if (colon == NULL) return false;
        size_t hlen = (size_t) (colon - address);
        if (hlen == 0 || hlen >= host_len) return false;
        memcpy(host, address, hlen);
        host[hlen] = 0;
    }

    const char *port_str = colon + 1;
    size_t plen = strlen(port_str);
    if (plen == 0 || plen >= port_len) return false;
    memcpy(port, port_str, plen);
    port[plen] = 0;
    return true;
}

static void on_attempt_handle_closed(uv_handle_t *h) {
    struct port_check_attempt_s *attempt = h->data;
    attempt->pending_handle_closes--;
    if (attempt->pending_handle_closes > 0) return;

    struct health_check_s *check = attempt->check;
    bool passed = attempt->passed;
    char err[sizeof(attempt->err_buf)];
    memcpy(err, attempt->err_buf, sizeof(err));
    free(attempt);
    on_check_attempt_complete(check, passed, err[0] ? err : NULL);
}

static void complete_port_check(struct port_check_attempt_s *attempt, bool passed, const char *err) {
    if (attempt->completed) return;
    attempt->completed = true;
    attempt->passed = passed;
    attempt->err_buf[0] = 0;
    if (err) snprintf(attempt->err_buf, sizeof(attempt->err_buf), "%s", err);

    if (!uv_is_closing((uv_handle_t *) &attempt->timeout_timer)) {
        uv_timer_stop(&attempt->timeout_timer);
    }
    attempt->pending_handle_closes = 2;
    uv_close((uv_handle_t *) &attempt->timeout_timer, on_attempt_handle_closed);
    uv_close((uv_handle_t *) &attempt->sock, on_attempt_handle_closed);
}

static void on_port_check_connect(uv_connect_t *req, int status) {
    struct port_check_attempt_s *attempt = req->handle->data;
    if (attempt->completed) return;
    complete_port_check(attempt, status == 0, status == 0 ? NULL : uv_strerror(status));
}

static void on_port_check_resolved(uv_getaddrinfo_t *req, int status, struct addrinfo *res) {
    struct port_check_attempt_s *attempt = req->data;
    if (attempt->completed) {
        if (res) uv_freeaddrinfo(res);
        return;
    }
    if (status != 0) {
        complete_port_check(attempt, false, uv_strerror(status));
        return;
    }

    int rc = uv_tcp_connect(&attempt->connect_req, &attempt->sock, res->ai_addr, on_port_check_connect);
    uv_freeaddrinfo(res);
    if (rc != 0) {
        complete_port_check(attempt, false, uv_strerror(rc));
    }
}

static void on_port_check_timeout(uv_timer_t *t) {
    struct port_check_attempt_s *attempt = t->data;
    if (attempt->completed) return;
    complete_port_check(attempt, false, "timed out");
}

static void start_port_check(struct health_check_s *check) {
    const ziti_port_check *cfg = check->cfg;
    uv_loop_t *loop = check->hc->host_ctx->tnlr_ctx->loop;

    struct port_check_attempt_s *attempt = calloc(1, sizeof(*attempt));
    attempt->check = check;

    uv_timer_init(loop, &attempt->timeout_timer);
    attempt->timeout_timer.data = attempt;
    uv_timer_start(&attempt->timeout_timer, on_port_check_timeout, (uint64_t) check->timeout_ms, 0);

    uv_tcp_init(loop, &attempt->sock);
    attempt->sock.data = attempt;

    char host[256];
    char port[16];
    if (!split_host_port(cfg->address, host, sizeof(host), port, sizeof(port))) {
        complete_port_check(attempt, false, "invalid address");
        return;
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    attempt->resolve_req.data = attempt;
    int rc = uv_getaddrinfo(loop, &attempt->resolve_req, on_port_check_resolved, host, port, &hints);
    if (rc != 0) {
        complete_port_check(attempt, false, uv_strerror(rc));
    }
}

/* ---------------------------------------------------------------------- */
/* http checks                                                             */
/* ---------------------------------------------------------------------- */

static void on_http_check_client_closed(tlsuv_http_t *clt) {
    struct http_check_attempt_s *attempt = clt->data;
    struct health_check_s *check = attempt->check;
    bool passed = attempt->passed;
    char err[sizeof(attempt->err_buf)];
    memcpy(err, attempt->err_buf, sizeof(err));
    free(attempt);
    on_check_attempt_complete(check, passed, err[0] ? err : NULL);
}

static void finish_http_check(struct http_check_attempt_s *attempt, bool passed, const char *err) {
    if (attempt->finished) return;
    attempt->finished = true;
    attempt->passed = passed;
    attempt->err_buf[0] = 0;
    if (err) snprintf(attempt->err_buf, sizeof(attempt->err_buf), "%s", err);
    tlsuv_http_close(&attempt->client, on_http_check_client_closed);
}

static void on_http_check_body(tlsuv_http_req_t *req, char *body, ssize_t len) {
    struct http_check_attempt_s *attempt = req->data;
    if (attempt->finished) return;

    if (len < 0) {
        const ziti_http_check *cfg = attempt->check->cfg;
        bool status_ok = (len == UV_EOF) && attempt->status_code == attempt->check->resolved_expect_status;
        bool body_ok = true;
        if (status_ok && cfg->expect_in_body != NULL && cfg->expect_in_body[0] != '\0') {
            attempt->body_buf[attempt->body_len] = 0;
            body_ok = strstr(attempt->body_buf, cfg->expect_in_body) != NULL;
        }
        if (len != UV_EOF) {
            finish_http_check(attempt, false, "error reading response body");
        } else if (!status_ok) {
            finish_http_check(attempt, false, "unexpected response status");
        } else if (!body_ok) {
            finish_http_check(attempt, false, "response body did not match expected content");
        } else {
            finish_http_check(attempt, true, NULL);
        }
        return;
    }

    if (attempt->body_len < sizeof(attempt->body_buf) - 1) {
        size_t room = sizeof(attempt->body_buf) - 1 - attempt->body_len;
        size_t n = (size_t) len < room ? (size_t) len : room;
        memcpy(attempt->body_buf + attempt->body_len, body, n);
        attempt->body_len += n;
    }
    // else: response body exceeds our inspection cap; the excess is silently dropped.
    // expectInBody matching only ever needs to see the leading HTTP_CHECK_BODY_CAP bytes.
}

static void on_http_check_resp(tlsuv_http_resp_t *resp, void *ctx) {
    struct http_check_attempt_s *attempt = ctx;
    if (resp->code < 0) {
        finish_http_check(attempt, false, uv_strerror(resp->code));
        return;
    }
    attempt->status_code = resp->code;
    resp->body_cb = on_http_check_body;
}

static void start_http_check(struct health_check_s *check) {
    const ziti_http_check *cfg = check->cfg;
    uv_loop_t *loop = check->hc->host_ctx->tnlr_ctx->loop;

    struct tlsuv_url_s u;
    if (tlsuv_parse_url(&u, cfg->url) != 0 || u.scheme == NULL || u.hostname == NULL) {
        on_check_attempt_complete(check, false, "invalid url");
        return;
    }

    bool is_https = u.scheme_len == 5 && strncasecmp(u.scheme, "https", 5) == 0;
    uint16_t port = u.port != 0 ? u.port : (is_https ? 443 : 80);

    char base_url[300];
    snprintf(base_url, sizeof(base_url), "%.*s://%.*s:%u",
             (int) u.scheme_len, u.scheme, (int) u.hostname_len, u.hostname, port);

    struct http_check_attempt_s *attempt = calloc(1, sizeof(*attempt));
    attempt->check = check;

    if (tlsuv_http_init(loop, &attempt->client, base_url) != 0) {
        free(attempt);
        on_check_attempt_complete(check, false, "failed to initialize http client");
        return;
    }
    attempt->client.data = attempt;
    tlsuv_http_connect_timeout(&attempt->client, check->timeout_ms);
    tlsuv_http_request_timeout(&attempt->client, check->timeout_ms);
    tlsuv_http_idle_keepalive(&attempt->client, 0); // one-shot check; don't linger afterward

    char path[600];
    if (u.path_len > 0) {
        snprintf(path, sizeof(path), "%.*s", (int) u.path_len, u.path);
    } else {
        snprintf(path, sizeof(path), "/");
    }
    if (u.query_len > 0) {
        size_t used = strlen(path);
        snprintf(path + used, sizeof(path) - used, "?%.*s", (int) u.query_len, u.query);
    }

    const char *method = (cfg->method != NULL && cfg->method[0] != '\0') ? cfg->method : "GET";
    tlsuv_http_req_t *req = tlsuv_http_req(&attempt->client, method, path, on_http_check_resp, attempt);
    if (req == NULL) {
        finish_http_check(attempt, false, "failed to create http request");
        return;
    }
    if (cfg->body != NULL && cfg->body[0] != '\0') {
        tlsuv_http_req_data(req, cfg->body, strlen(cfg->body), NULL);
    }
}

/* ---------------------------------------------------------------------- */
/* lifecycle                                                               */
/* ---------------------------------------------------------------------- */

static void on_check_timer_closed(uv_handle_t *h) {
    struct health_check_s *check = h->data;
    check_teardown_progress(check);
}

static void check_teardown_progress(struct health_check_s *check) {
    check->pending_closes--;
    if (check->pending_closes > 0) return;

    struct health_checks_ctx_s *hc = check->hc;
    free(check->actions);
    free(check);

    hc->pending_closes--;
    if (hc->pending_closes == 0) {
        free(hc->checks);
        free(hc);
    }
}

health_checks_ctx_t *host_health_checks_start(struct hosted_service_ctx_s *host_ctx) {
    if (host_ctx->cfg_type != HOST_CFG_V1) {
        return NULL;
    }
    const ziti_host_cfg_v1 *cfg = host_ctx->cfg;

    int port_count = 0, http_count = 0;
    if (cfg->port_checks != NULL) {
        while (cfg->port_checks[port_count] != NULL) port_count++;
    }
    if (cfg->http_checks != NULL) {
        while (cfg->http_checks[http_count] != NULL) http_count++;
    }
    if (port_count == 0 && http_count == 0) {
        return NULL;
    }

    struct health_checks_ctx_s *hc = calloc(1, sizeof(*hc));
    hc->host_ctx = host_ctx;
    hc->baseline_cost = host_ctx->health_baseline_cost;
    hc->baseline_precedence = host_ctx->health_baseline_precedence;
    hc->current_cost = hc->next_cost = hc->baseline_cost;
    hc->current_precedence = hc->next_precedence = hc->baseline_precedence;

    hc->check_count = port_count + http_count;
    hc->checks = calloc((size_t) hc->check_count, sizeof(struct health_check_s *));

    int idx = 0;
    for (int i = 0; i < port_count; i++, idx++) {
        hc->checks[idx] = build_check(hc, CHECK_PORT, cfg->port_checks[i], i);
    }
    for (int i = 0; i < http_count; i++, idx++) {
        hc->checks[idx] = build_check(hc, CHECK_HTTP, cfg->http_checks[i], i);
    }

    ZITI_LOG(INFO, "hosted_service[%s] starting %d health check(s), baseline cost[%u] precedence[%u]",
             host_ctx->service_name, hc->check_count, hc->baseline_cost, hc->baseline_precedence);

    return hc;
}

void host_health_checks_stop(health_checks_ctx_t *hc) {
    if (hc == NULL || hc->stopping) return;
    hc->stopping = true;

    if (hc->check_count == 0) {
        free(hc->checks);
        free(hc);
        return;
    }

    hc->pending_closes = hc->check_count;
    for (int i = 0; i < hc->check_count; i++) {
        struct health_check_s *check = hc->checks[i];
        check->stopping = true;
        check->pending_closes = check->attempt_in_flight ? 2 : 1;
        uv_timer_stop(&check->timer);
        uv_close((uv_handle_t *) &check->timer, on_check_timer_closed);
        // any in-flight attempt is left to complete on its own -- both port and http
        // attempts are bounded by check->timeout_ms, so this delays freeing that one
        // check by at most one timeout, and it calls back into on_check_attempt_complete
        // (which sees check->stopping and progresses teardown) rather than recording a
        // result once it finishes.
    }
}
