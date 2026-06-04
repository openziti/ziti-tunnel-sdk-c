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

package integration_test

import (
	"testing"
	"time"

	"github.com/openziti/ziti-tunnel-sdk-c/tests/integration/testutil"
	"github.com/stretchr/testify/require"
)

func TestEnableMFA(t *testing.T) {
	t.Run("acceptsJwtEnrolledIdentity", acceptsJwtEnrolledIdentity)
	t.Run("acceptsTotpRequiredAuthPolicy", acceptsTotpRequiredAuthPolicy)
}

func TestVerifyMFA(t *testing.T) {
	t.Run("acceptsValidTotp", verifyAcceptsValidTotp)
	t.Run("rejectsInvalidTotp", verifyRejectsInvalidTotp)
}

func TestMFAReauthentication(t *testing.T) {
	t.Run("acceptsValidTotp", reauthAcceptsValidTotp)
	t.Run("acceptsRecoveryCode", reauthAcceptsRecoveryCode)
	t.Run("rejectsInvalidTotp", reauthRejectsInvalidTotp)
}

func TestRemoveMFA(t *testing.T) {
	t.Run("acceptsValidTotp", removeAcceptsValidTotp)
	t.Run("acceptsRecoveryCode", removeAcceptsRecoveryCode)
	t.Run("rejectsInvalidTotp", removeRejectsInvalidTotp)
}

func acceptsJwtEnrolledIdentity(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		enrollment, _ := testutil.SetupMFA(t, state.overlay, state.zetClient, testutil.IdentityName(t))

		require.False(t, enrollment.IsVerified, "EnableMFA Data.IsVerified should be false before verify_mfa")
	})
}

func acceptsTotpRequiredAuthPolicy(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		t.Skip("Tracking https://github.com/openziti/desktop-edge-win/issues/947 and https://openziti.discourse.group/t/enrolling-mfa-totp-from-zdew-fails/5482 - EnableMFA fails with 'failed to authenticate' for identities bound to TOTP-required auth policies")

		enrollment, _ := testutil.SetupMFA(t, state.overlay, state.zetClient, testutil.IdentityName(t))

		require.False(t, enrollment.IsVerified, "EnableMFA Data.IsVerified should be false before verify_mfa")
	})
}

func verifyAcceptsValidTotp(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		testutil.SetupVerifiedMFA(t, state.overlay, state.zetClient, testutil.IdentityName(t))
	})
}

func verifyRejectsInvalidTotp(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		name := testutil.IdentityName(t)
		enrollment, _ := testutil.SetupMFA(t, state.overlay, state.zetClient, name)

		state.zetClient.VerifyMFA(t, enrollment.Identifier, "000000").AssertFail(t, 500, "the token provided was invalid")
	})
}

func reauthAcceptsValidTotp(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		name := testutil.IdentityName(t)
		enrollment, secret := testutil.SetupVerifiedMFA(t, state.overlay, state.zetClient, name)

		testutil.SetIdentityActive(t, state.zetClient, enrollment.Identifier, false)
		testutil.SetIdentityActive(t, state.zetClient, enrollment.Identifier, true)

		state.zetClient.WaitForMfaEvent(t, "auth_challenge", name)

		code, err := testutil.GenerateTOTP(secret, time.Now())
		require.NoError(t, err, "failed to compute TOTP")

		state.zetClient.SubmitMFA(t, enrollment.Identifier, code).AssertSuccess(t)

		submitEvt := state.zetClient.WaitForMfaEvent(t, "mfa_auth_status", name)
		require.True(t, submitEvt.Successful, "mfa:mfa_auth_status Successful=%t after SubmitMFA", submitEvt.Successful)
	})
}

func reauthAcceptsRecoveryCode(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		name := testutil.IdentityName(t)
		enrollment, _ := testutil.SetupVerifiedMFA(t, state.overlay, state.zetClient, name)

		testutil.SetIdentityActive(t, state.zetClient, enrollment.Identifier, false)
		testutil.SetIdentityActive(t, state.zetClient, enrollment.Identifier, true)

		state.zetClient.WaitForMfaEvent(t, "auth_challenge", name)

		state.zetClient.SubmitMFA(t, enrollment.Identifier, enrollment.RecoveryCodes[0]).AssertSuccess(t)

		submitEvt := state.zetClient.WaitForMfaEvent(t, "mfa_auth_status", name)
		require.True(t, submitEvt.Successful, "mfa:mfa_auth_status Successful=%t after SubmitMFA", submitEvt.Successful)
	})
}

func reauthRejectsInvalidTotp(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		name := testutil.IdentityName(t)
		enrollment, _ := testutil.SetupVerifiedMFA(t, state.overlay, state.zetClient, name)

		testutil.SetIdentityActive(t, state.zetClient, enrollment.Identifier, false)
		testutil.SetIdentityActive(t, state.zetClient, enrollment.Identifier, true)

		state.zetClient.WaitForMfaEvent(t, "auth_challenge", name)

		state.zetClient.SubmitMFA(t, enrollment.Identifier, "000000").AssertFail(t, 500, "the token provided was invalid")
	})
}

func removeAcceptsValidTotp(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		name := testutil.IdentityName(t)
		enrollment, secret := testutil.SetupVerifiedMFA(t, state.overlay, state.zetClient, name)

		code, err := testutil.GenerateTOTP(secret, time.Now())
		require.NoError(t, err, "failed to compute TOTP")

		state.zetClient.RemoveMFA(t, enrollment.Identifier, code).AssertSuccess(t)

		removeEvt := state.zetClient.WaitForMfaEvent(t, "enrollment_remove", name)
		require.True(t, removeEvt.Successful, "mfa:enrollment_remove Successful=%t after RemoveMFA", removeEvt.Successful)
	})
}

func removeAcceptsRecoveryCode(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		name := testutil.IdentityName(t)
		enrollment, _ := testutil.SetupVerifiedMFA(t, state.overlay, state.zetClient, name)

		state.zetClient.RemoveMFA(t, enrollment.Identifier, enrollment.RecoveryCodes[0]).AssertSuccess(t)

		removeEvt := state.zetClient.WaitForMfaEvent(t, "enrollment_remove", name)
		require.True(t, removeEvt.Successful, "mfa:enrollment_remove Successful=%t after RemoveMFA", removeEvt.Successful)
	})
}

func removeRejectsInvalidTotp(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		name := testutil.IdentityName(t)
		enrollment, _ := testutil.SetupVerifiedMFA(t, state.overlay, state.zetClient, name)

		state.zetClient.RemoveMFA(t, enrollment.Identifier, "000000").AssertFail(t, 500, "the token provided was invalid")
	})
}
