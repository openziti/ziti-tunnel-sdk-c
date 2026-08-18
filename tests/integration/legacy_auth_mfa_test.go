//go:build slowtests

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

// Every test here restarts the tunneler, and several wait out a silence window, so the set
// costs minutes. It sits behind the slowtests tag and runs nightly.
//
//	go test . -tags slowtests -config config.json

package integration_test

import (
	"testing"
	"time"

	"github.com/openziti/ziti-tunnel-sdk-c/tests/integration/testutil"
	"github.com/stretchr/testify/require"
)

// MFA state across tunneler restarts, on either auth path.
//
// A legacy controller never tells the client whether an identity has TOTP enrolled: the auth
// query is byte-identical for an enrolled identity and one that has never enrolled. The sdk
// reads the missing field as "not enrolled" and asks the client to enroll, so an enrolled
// user gets an enrollment button instead of a code box, and enrollment fails on a partially
// authenticated session.
//
// An enrolled identity must be asked for a code after a restart whichever path the overlay
// runs on, so most of these run on both. The two that require legacy say so.
func TestLegacyAuthMFA(t *testing.T) {
	t.Run("restartOffersCodePromptForEnrolledIdentity", restartOffersCodePromptForEnrolledIdentity)
	t.Run("disableEnableOffersCodePromptForEnrolledIdentity", disableEnableOffersCodePromptForEnrolledIdentity)
	t.Run("restartKeepsPersistedMfaEnabled", restartKeepsPersistedMfaEnabled)
	t.Run("recoversWhenPersistedMfaEnabledIsWrong", recoversWhenPersistedMfaEnabledIsWrong)
	t.Run("repeatedRestartsKeepOfferingCodePrompt", repeatedRestartsKeepOfferingCodePrompt)
	t.Run("restartAcceptsRecoveryCode", restartAcceptsRecoveryCode)
	t.Run("acceptedCodeEndsThePrompting", acceptedCodeEndsThePrompting)
	t.Run("twoIdentitiesKeepSeparateMfaState", twoIdentitiesKeepSeparateMfaState)
	t.Run("removeMfaThenRestartStopsPrompting", removeMfaThenRestartStopsPrompting)
	t.Run("adminRemovedMfaStopsPromptingAfterRestart", adminRemovedMfaStopsPromptingAfterRestart)
	t.Run("migratingToOidcKeepsTheIdentityEnrolled", migratingToOidcKeepsTheIdentityEnrolled)
}

// Enroll MFA, verify it, restart the tunneler, and expect a code prompt. Submit a real code
// and the identity is authenticated again.
//
// On legacy auth without the fix, the tunneler passes the sdk's enrollment request straight
// through, so auth_challenge never arrives and this fails waiting for it.
func restartOffersCodePromptForEnrolledIdentity(t *testing.T) {
	testutil.RunWithTimeoutOf(t, 60*time.Second, func(t *testing.T) {
		idName := "test_legacy_mfa_restart_prompt"
		enrollment, secret := testutil.EnrollAndVerifyMFA(t, state.overlay, state.zetClient, idName)

		require.NoError(t, state.zetClient.Restart(), "restart %s\n%s", state.zetClient.Discriminator, state.zetClient.LogPath())

		state.zetClient.WaitForMfaEvent(t, "auth_challenge", idName)

		code := testutil.GenerateTOTP(t, secret, time.Now())
		submitResp := state.zetClient.SubmitMFA(t, enrollment.Identifier, code)
		submitResp.AssertSuccess()

		updatedEvent := state.zetClient.WaitForIdentityEvent(t, "updated", idName)
		updatedEvent.AssertMfaAuthenticated()
	})
}

// Same as the restart case, but re-authentication is triggered by toggling the identity off
// and on. The prompt must be a code prompt, and the state on disk must survive the toggle.
//
// A toggle never reloads config.json, so whatever the running process holds in memory is
// what it uses.
func disableEnableOffersCodePromptForEnrolledIdentity(t *testing.T) {
	testutil.RunWithTimeoutOf(t, 60*time.Second, func(t *testing.T) {
		idName := "test_legacy_mfa_toggle_prompt"
		enrollment, secret := testutil.EnrollAndVerifyMFA(t, state.overlay, state.zetClient, idName)

		state.zetClient.DisableEnableIdentity(t, enrollment.Identifier)

		state.zetClient.WaitForMfaEvent(t, "auth_challenge", idName)

		code := testutil.GenerateTOTP(t, secret, time.Now())
		submitResp := state.zetClient.SubmitMFA(t, enrollment.Identifier, code)
		submitResp.AssertSuccess()

		updatedEvent := state.zetClient.WaitForIdentityEvent(t, "updated", idName)
		updatedEvent.AssertMfaAuthenticated()

		persisted := state.zetClient.PersistedIdentity(t, enrollment.Identifier)
		require.Equal(t, true, persisted["MfaEnabled"], "config.json says MfaEnabled=%v after a toggle for enrolled identity %q", persisted["MfaEnabled"], idName)
	})
}

// Restart, then check that the two places the client reports its state agree: the status it
// pushes to clients, and config.json on disk. Both must still say the identity is enrolled
// and now needs a code.
//
// On legacy auth without the fix, the enrollment request overwrites the value loaded from
// disk, the UI is told the identity is not enrolled, and the next routine save writes that
// to the file, so the file stops agreeing with the controller.
func restartKeepsPersistedMfaEnabled(t *testing.T) {
	testutil.RunWithTimeoutOf(t, 60*time.Second, func(t *testing.T) {
		idName := "test_legacy_mfa_restart_state"
		enrollment, _ := testutil.EnrollAndVerifyMFA(t, state.overlay, state.zetClient, idName)

		require.NoError(t, state.zetClient.Restart(), "restart %s\n%s", state.zetClient.Discriminator, state.zetClient.LogPath())

		state.zetClient.WaitForMfaEvent(t, "auth_challenge", idName)

		state.zetClient.ReconnectEvents(t)
		after := state.zetClient.WaitForStatusEvent(t)
		identity := findIdentityInStatus(t, after, enrollment.Identifier)
		require.True(t, identity.MfaEnabled, "status says MfaEnabled=false for enrolled identity %q", idName)
		require.True(t, identity.MfaNeeded, "status says MfaNeeded=false while waiting for a code for %q", idName)

		persisted := state.zetClient.PersistedIdentity(t, enrollment.Identifier)
		require.Equal(t, true, persisted["MfaEnabled"], "config.json says MfaEnabled=%v for enrolled identity %q", persisted["MfaEnabled"], idName)
	})
}

// Stage the state older clients left behind: enroll MFA, stop the tunneler, rewrite
// config.json to say the identity is not enrolled, start again.
//
// The client has nothing trustworthy to prefer, so the enrollment request legitimately
// stands and the test asserts it. It then clicks the button the UI would offer, expects that
// to fail on the partially authenticated session, and requires a code prompt to follow.
func recoversWhenPersistedMfaEnabledIsWrong(t *testing.T) {
	// asserts enrollment_required actually arrives, which needs a controller that withholds
	// the enrollment state
	state.overlay.RequireLegacyAuth(t)

	testutil.RunWithTimeoutOf(t, 90*time.Second, func(t *testing.T) {
		idName := "test_legacy_mfa_corrupted_state"
		enrollment, secret := testutil.EnrollAndVerifyMFA(t, state.overlay, state.zetClient, idName)

		state.zetClient.Stop()
		state.zetClient.SetPersistedMfaEnabled(t, enrollment.Identifier, false)
		require.NoError(t, state.zetClient.Start(), "start %s\n%s", state.zetClient.Discriminator, state.zetClient.LogPath())

		state.zetClient.WaitForMfaEvent(t, "enrollment_required", idName)

		enableResp := state.zetClient.EnableMFA(t, enrollment.Identifier)
		enableResp.AssertFail(500, "failed to authenticate")

		state.zetClient.WaitForMfaEvent(t, "auth_challenge", idName)

		code := testutil.GenerateTOTP(t, secret, time.Now())
		submitResp := state.zetClient.SubmitMFA(t, enrollment.Identifier, code)
		submitResp.AssertSuccess()

		updatedEvent := state.zetClient.WaitForIdentityEvent(t, "updated", idName)
		updatedEvent.AssertMfaAuthenticated()
	})
}

// Restart twice, answering the prompt each time.
//
// One restart proves the client reads its state correctly; two prove it also wrote it back
// correctly. If the first pass persists the wrong value, the second restart loads it.
func repeatedRestartsKeepOfferingCodePrompt(t *testing.T) {
	testutil.RunWithTimeoutOf(t, 90*time.Second, func(t *testing.T) {
		idName := "test_legacy_mfa_repeat_restart"
		enrollment, secret := testutil.EnrollAndVerifyMFA(t, state.overlay, state.zetClient, idName)

		// Each pass needs a credential the controller has not seen. Reusing a TOTP code
		// inside its window is rejected, so rather than idle for a new window the second
		// pass answers with a recovery code, which is single-use by design.
		answers := []string{testutil.GenerateTOTP(t, secret, time.Now()), enrollment.RecoveryCodes[0]}

		for pass, answer := range answers {
			require.NoError(t, state.zetClient.Restart(), "restart %d of %s\n%s", pass+1, state.zetClient.Discriminator, state.zetClient.LogPath())

			state.zetClient.WaitForMfaEvent(t, "auth_challenge", idName)

			submitResp := state.zetClient.SubmitMFA(t, enrollment.Identifier, answer)
			submitResp.AssertSuccess()

			updatedEvent := state.zetClient.WaitForIdentityEvent(t, "updated", idName)
			updatedEvent.AssertMfaAuthenticated()

			persisted := state.zetClient.PersistedIdentity(t, enrollment.Identifier)
			require.Equal(t, true, persisted["MfaEnabled"], "config.json says MfaEnabled=%v after restart %d of %q", persisted["MfaEnabled"], pass+1, idName)
		}
	})
}

// Answer the post-restart prompt with a recovery code rather than a TOTP code.
//
// A user who has lost their authenticator uses a recovery code, and that path runs through
// different controller endpoints than TOTP. The existing reauth coverage exercises recovery
// codes after a toggle; this one does it after a restart, where the client has just reloaded
// its state from disk.
func restartAcceptsRecoveryCode(t *testing.T) {
	testutil.RunWithTimeoutOf(t, 60*time.Second, func(t *testing.T) {
		idName := "test_legacy_mfa_restart_recovery"
		enrollment, _ := testutil.EnrollAndVerifyMFA(t, state.overlay, state.zetClient, idName)

		require.NoError(t, state.zetClient.Restart(), "restart %s\n%s", state.zetClient.Discriminator, state.zetClient.LogPath())

		state.zetClient.WaitForMfaEvent(t, "auth_challenge", idName)

		submitResp := state.zetClient.SubmitMFA(t, enrollment.Identifier, enrollment.RecoveryCodes[0])
		submitResp.AssertSuccess()

		updatedEvent := state.zetClient.WaitForIdentityEvent(t, "updated", idName)
		updatedEvent.AssertMfaAuthenticated()
	})
}

// Answer the prompt, then watch for a while and expect silence.
//
// The reported symptom was not a missing prompt but an endless run of them, one every ten
// seconds. That happens when the client keeps tearing its session down and
// re-authenticating, so every cycle asks again.
func acceptedCodeEndsThePrompting(t *testing.T) {
	testutil.RunWithTimeoutOf(t, 90*time.Second, func(t *testing.T) {
		idName := "test_legacy_mfa_quiet_after_code"
		enrollment, secret := testutil.EnrollAndVerifyMFA(t, state.overlay, state.zetClient, idName)

		require.NoError(t, state.zetClient.Restart(), "restart %s\n%s", state.zetClient.Discriminator, state.zetClient.LogPath())

		state.zetClient.WaitForMfaEvent(t, "auth_challenge", idName)

		code := testutil.GenerateTOTP(t, secret, time.Now())
		submitResp := state.zetClient.SubmitMFA(t, enrollment.Identifier, code)
		submitResp.AssertSuccess()

		updatedEvent := state.zetClient.WaitForIdentityEvent(t, "updated", idName)
		updatedEvent.AssertMfaAuthenticated()

		// longer than the ten second cycle a re-prompting client runs on
		state.zetClient.AssertNoMfaEvent(t, "auth_challenge", idName, 12*time.Second)
		state.zetClient.AssertNoMfaEvent(t, "enrollment_required", idName, time.Second)
	})
}

// Load one identity with MFA and one without, in the same tunneler, then restart.
//
// The enrolled one must be asked for a code; the other must not be asked for anything. This
// catches a fix that reads or writes MFA state for the wrong identity, which a single
// identity test cannot see.
func twoIdentitiesKeepSeparateMfaState(t *testing.T) {
	testutil.RunWithTimeoutOf(t, 90*time.Second, func(t *testing.T) {
		mfaName := "test_legacy_mfa_pair_enrolled"
		plainName := "test_legacy_mfa_pair_plain"

		enrollment, secret := testutil.EnrollAndVerifyMFA(t, state.overlay, state.zetClient, mfaName)
		plain := testutil.FetchAndEnrollJwt(t, state.overlay, state.zetClient, plainName)
		state.zetClient.WaitForControllerEvent(t, "connected", plainName)

		require.NoError(t, state.zetClient.Restart(), "restart %s\n%s", state.zetClient.Discriminator, state.zetClient.LogPath())

		state.zetClient.WaitForMfaEvent(t, "auth_challenge", mfaName)
		state.zetClient.AssertNoMfaEvent(t, "auth_challenge", plainName, 2*time.Second)
		state.zetClient.AssertNoMfaEvent(t, "enrollment_required", plainName, time.Second)

		code := testutil.GenerateTOTP(t, secret, time.Now())
		state.zetClient.SubmitMFA(t, enrollment.Identifier, code).AssertSuccess()
		state.zetClient.WaitForIdentityEvent(t, "updated", mfaName).AssertMfaAuthenticated()

		state.zetClient.ReconnectEvents(t)
		after := state.zetClient.WaitForStatusEvent(t)
		require.True(t, findIdentityInStatus(t, after, enrollment.Identifier).MfaEnabled, "status says MfaEnabled=false for enrolled identity %q", mfaName)
		require.False(t, findIdentityInStatus(t, after, plain.Id.Identifier).MfaEnabled, "status says MfaEnabled=true for identity %q, which never enrolled", plainName)
	})
}

// Remove MFA from the client, then restart.
//
// The existing coverage checks that removal is accepted; this checks that it stuck. After a
// restart the identity must come up with nothing pending and no prompt.
func removeMfaThenRestartStopsPrompting(t *testing.T) {
	testutil.RunWithTimeoutOf(t, 60*time.Second, func(t *testing.T) {
		idName := "test_legacy_mfa_removed_then_restart"
		enrollment, secret := testutil.EnrollAndVerifyMFA(t, state.overlay, state.zetClient, idName)

		code := testutil.GenerateTOTP(t, secret, time.Now())
		state.zetClient.RemoveMFA(t, enrollment.Identifier, code).AssertSuccess()
		state.zetClient.WaitForMfaEvent(t, "enrollment_remove", idName).AssertSuccess()

		require.NoError(t, state.zetClient.Restart(), "restart %s\n%s", state.zetClient.Discriminator, state.zetClient.LogPath())
		state.zetClient.WaitForControllerEvent(t, "connected", idName)

		state.zetClient.AssertNoMfaEvent(t, "auth_challenge", idName, 2*time.Second)
		state.zetClient.AssertNoMfaEvent(t, "enrollment_required", idName, time.Second)

		persisted := state.zetClient.PersistedIdentity(t, enrollment.Identifier)
		require.Equal(t, false, persisted["MfaEnabled"], "config.json says MfaEnabled=%v after MFA was removed from %q", persisted["MfaEnabled"], idName)
	})
}

// An administrator clears the identity's MFA enrollment on the controller while the client
// still believes it is enrolled, then the client restarts.
//
// The identity must come back with no prompt at all. This is the one case where the
// client's stored state is deliberately ahead of the controller's.
func adminRemovedMfaStopsPromptingAfterRestart(t *testing.T) {
	testutil.RunWithTimeoutOf(t, 60*time.Second, func(t *testing.T) {
		idName := "test_legacy_mfa_admin_removed"
		enrollment, _ := testutil.EnrollAndVerifyMFA(t, state.overlay, state.zetClient, idName)
		require.True(t, state.overlay.IdentityMfaEnabled(t, idName), "controller says %q is not enrolled after verifying MFA", idName)

		state.overlay.RemoveIdentityMFA(t, idName)
		require.False(t, state.overlay.IdentityMfaEnabled(t, idName), "controller still says %q is enrolled after an admin removed MFA", idName)

		require.NoError(t, state.zetClient.Restart(), "restart %s\n%s", state.zetClient.Discriminator, state.zetClient.LogPath())
		state.zetClient.WaitForControllerEvent(t, "connected", idName)

		state.zetClient.AssertNoMfaEvent(t, "auth_challenge", idName, 2*time.Second)
		state.zetClient.AssertNoMfaEvent(t, "enrollment_required", idName, time.Second)

		state.zetClient.ReconnectEvents(t)
		after := state.zetClient.WaitForStatusEvent(t)
		identity := findIdentityInStatus(t, after, enrollment.Identifier)
		require.False(t, identity.MfaNeeded, "status says MfaNeeded=true for %q after an admin removed MFA", idName)
	})
}

// Enroll on a legacy controller, then have an administrator put OIDC back and restart it.
//
// This is the migration support recommends, so the client has to survive it: the identity is
// still enrolled afterwards and is still asked for a code, now because the controller says
// so rather than because the client remembered. Restores legacy auth on the way out.
func migratingToOidcKeepsTheIdentityEnrolled(t *testing.T) {
	state.overlay.RequireLegacyAuth(t)

	testutil.RunWithTimeoutOf(t, 180*time.Second, func(t *testing.T) {
		idName := "test_legacy_mfa_oidc_migration"
		enrollment, secret := testutil.EnrollAndVerifyMFA(t, state.overlay, state.zetClient, idName)

		require.NoError(t, state.zetClient.Restart(), "restart %s\n%s", state.zetClient.Discriminator, state.zetClient.LogPath())
		state.zetClient.WaitForMfaEvent(t, "auth_challenge", idName)

		t.Cleanup(func() { state.overlay.RestoreLegacyAuth(t) })
		state.overlay.EnableOidc(t)

		require.NoError(t, state.zetClient.Restart(), "restart %s after the OIDC migration\n%s", state.zetClient.Discriminator, state.zetClient.LogPath())
		state.zetClient.WaitForMfaEvent(t, "auth_challenge", idName)

		code := testutil.GenerateTOTP(t, secret, time.Now())
		submitResp := state.zetClient.SubmitMFA(t, enrollment.Identifier, code)
		submitResp.AssertSuccess()

		updatedEvent := state.zetClient.WaitForIdentityEvent(t, "updated", idName)
		updatedEvent.AssertMfaAuthenticated()

		require.True(t, state.overlay.IdentityMfaEnabled(t, idName), "controller says %q is not enrolled after the OIDC migration", idName)
		persisted := state.zetClient.PersistedIdentity(t, enrollment.Identifier)
		require.Equal(t, true, persisted["MfaEnabled"], "config.json says MfaEnabled=%v after the OIDC migration", persisted["MfaEnabled"])
	})
}
