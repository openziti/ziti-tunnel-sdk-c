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

// What the library knows of an identity's authentication: the state of the login, what a partial login waits for,
// and whether TOTP is enrolled. It is kept from the ziti events the library already receives and is returned by the
// ListIdentities command.
//
// This file includes ziti_tunnel_cbs.h only, never ziti_instance.h: that header defines a static CMD_CTX, which would
// give this file a copy of its own.

#include <string.h>

#include <ziti/ziti_log.h>
#include <ziti/ziti_tunnel_cbs.h>

IMPL_ENUM(tnl_auth_state, TNL_AUTH_STATE)
IMPL_ENUM(tnl_auth_needs, TNL_AUTH_NEEDS)
IMPL_ENUM(tnl_mfa_enrolled, TNL_MFA_ENROLLED)

// auth_state and auth_needs change together, so that auth_needs is none for every known state but partial
static void set_state(struct ziti_instance_s *inst, tnl_auth_state state, tnl_auth_needs needs) {
    if (inst->auth_state != state || inst->auth_needs != needs) {
        ZITI_LOG(DEBUG, "identity[%s] auth_state[%s] auth_needs[%s] -> auth_state[%s] auth_needs[%s]", inst->identifier,
                 tnl_auth_state_name(inst->auth_state), tnl_auth_needs_name(inst->auth_needs),
                 tnl_auth_state_name(state), tnl_auth_needs_name(needs));
    }
    inst->auth_state = state;
    inst->auth_needs = needs;
}

static void apply_context_event(struct ziti_instance_s *inst, const struct ziti_context_event *ev) {
    // The SDK also sends the list of controllers in a context event, with no status of its own: zero, which is
    // ZITI_OK. It says nothing about authentication. (A list with no controller in it carries no mark and still reads
    // as ZITI_OK; the SDK has nothing to report then.)
    if (ev->ctrl_count > 0 || ev->ctrl_details != NULL) {
        return;
    }

    switch (ev->ctrl_status) {
        case ZITI_OK:
            set_state(inst, tnl_auth_state_authenticated, tnl_auth_needs_none);
            ziti_instance_sync_mfa_enrolled(inst);
            break;
        case ZITI_PARTIALLY_AUTHENTICATED:
            // the auth event that says what the login waits for follows; one that came already still holds
            set_state(inst, tnl_auth_state_partial,
                      inst->auth_state == tnl_auth_state_partial ? inst->auth_needs : tnl_auth_needs_Unknown);
            break;
        case ZITI_DISABLED:
            set_state(inst, tnl_auth_state_disabled, tnl_auth_needs_none);
            break;
        default:
            set_state(inst, tnl_auth_state_failed, tnl_auth_needs_none);
            break;
    }
}

// Known limit: an external login that the application starts on an identity that is authenticated already
// (ziti_use_ext_jwt_signer) sends login_external, and a failure of that login sends cannot_continue, with no event to
// say the identity is still in; they are folded like any other, so such an identity lists partial / failed until the
// SDK next reports a status. Ignoring them while authenticated would hide the real partial login of a session that
// is lost between ziti_auth_success and the identity data (the SDK has no public way to tell the two apart).
static void apply_auth_event(struct ziti_instance_s *inst, const struct ziti_auth_event *ev) {
    switch (ev->action) {
        case ziti_auth_enroll_totp:
            set_state(inst, tnl_auth_state_partial, tnl_auth_needs_totp_enroll);
            inst->mfa_enrolled = tnl_mfa_enrolled_not_enrolled;
            break;
        case ziti_auth_prompt_totp:
            // the controller asks for a code, which only an enrolled identity has: true before the identity data loads
            set_state(inst, tnl_auth_state_partial, tnl_auth_needs_totp_code);
            inst->mfa_enrolled = tnl_mfa_enrolled_enrolled;
            break;
        case ziti_auth_select_external:
        case ziti_auth_login_external:
            set_state(inst, tnl_auth_state_partial, tnl_auth_needs_ext_jwt);
            break;
        case ziti_auth_prompt_pin:
            set_state(inst, tnl_auth_state_partial, tnl_auth_needs_key_pin);
            break;
        case ziti_auth_success:
            set_state(inst, tnl_auth_state_authenticated, tnl_auth_needs_none);
            break;
        case ziti_auth_cannot_continue:
            set_state(inst, tnl_auth_state_failed, tnl_auth_needs_none);
            break;
        default:
            break;
    }
}

void ziti_instance_apply_event(struct ziti_instance_s *inst, const ziti_event_t *event) {
    if (inst == NULL || event == NULL) {
        return;
    }

    switch (event->type) {
        case ZitiContextEvent:
            apply_context_event(inst, &event->ctx);
            break;
        case ZitiAuthEvent:
            apply_auth_event(inst, &event->auth);
            break;
        default:
            break;
    }
}

void ziti_instance_sync_mfa_enrolled(struct ziti_instance_s *inst) {
    // ziti_is_mfa_enrolled() is false, not "unknown", until the identity data is loaded: what a prompt said stays
    if (inst == NULL || inst->ztx == NULL || ziti_get_identity(inst->ztx) == NULL) {
        return;
    }
    inst->mfa_enrolled = ziti_is_mfa_enrolled(inst->ztx) ? tnl_mfa_enrolled_enrolled : tnl_mfa_enrolled_not_enrolled;
}

void ziti_instance_set_enabled(struct ziti_instance_s *inst, bool enabled) {
    if (inst == NULL) {
        return;
    }

    if (enabled) {
        // Turning on an identity that is on starts nothing in the SDK, so no event would follow to restore what
        // is reset here: only a disabled identity starts over. Nothing has been seen since the restart; what is
        // known of MFA does not depend on it.
        if (inst->auth_state == tnl_auth_state_disabled) {
            set_state(inst, tnl_auth_state_Unknown, tnl_auth_needs_Unknown);
        }
    } else {
        set_state(inst, tnl_auth_state_disabled, tnl_auth_needs_none);
    }
}
