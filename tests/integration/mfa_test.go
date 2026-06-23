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

func TestMFAEnrollment(t *testing.T) {
	t.Run("enrollCompletesWithTotpRequiredPolicy", enrollCompletesWithTotpRequiredPolicy)
	t.Run("enrollRejectsInvalidTotp", enrollRejectsInvalidTotp)
}

func TestMFAReauthentication(t *testing.T) {
	t.Run("reauthAcceptsValidTotp", reauthAcceptsValidTotp)
	t.Run("reauthAcceptsRecoveryCode", reauthAcceptsRecoveryCode)
	t.Run("reauthRejectsRecoveryCodeReuse", reauthRejectsRecoveryCodeReuse)
	t.Run("reauthRejectsInvalidTotp", reauthRejectsInvalidTotp)
}

func TestRemoveMFA(t *testing.T) {
	t.Run("removeAcceptsValidTotp", removeAcceptsValidTotp)
	t.Run("removeAcceptsRecoveryCode", removeAcceptsRecoveryCode)
	t.Run("removeRejectsInvalidTotp", removeRejectsInvalidTotp)
}

func TestMFARecoveryCodes(t *testing.T) {
	t.Run("recoveryRejectsOldCodeAfterRegeneration", recoveryRejectsOldCodeAfterRegeneration)
}

func enrollCompletesWithTotpRequiredPolicy(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		name := "test_mfa_enable_totp_policy"
		added := testutil.FetchAndEnrollJwt(t, state.overlay, state.zetClient, name)
		require.False(t, added.Id.MfaEnabled, "identity:added MfaEnabled=%t before EnableMFA", added.Id.MfaEnabled)

		state.zetClient.WaitForMfaEvent(t, "enrollment_required", name)

		enableResp := state.zetClient.EnableMFA(t, added.Id.Identifier)
		enableResp.AssertSuccess()
		require.NotEmpty(t, enableResp.Data.ProvisioningUrl, "EnableMFA Data.ProvisioningUrl should be non-empty")
		require.NotEmpty(t, enableResp.Data.RecoveryCodes, "EnableMFA Data.RecoveryCodes should be non-empty")
		require.False(t, enableResp.Data.IsVerified, "EnableMFA Data.IsVerified should be false before verify_mfa")

		challengeEvent := state.zetClient.WaitForMfaEvent(t, "enrollment_challenge", name)
		challengeEvent.AssertSuccess()

		secret := testutil.ParseTOTPSecret(t, enableResp.Data.ProvisioningUrl)
		code := testutil.GenerateTOTP(t, secret, time.Now())

		verifyResp := state.zetClient.VerifyMFA(t, added.Id.Identifier, code)
		verifyResp.AssertSuccess()

		updatedEvent := state.zetClient.WaitForIdentityEvent(t, "updated", name)
		updatedEvent.AssertMfaAuthenticated()

		verificationEvent := state.zetClient.WaitForMfaEvent(t, "enrollment_verification", name)
		verificationEvent.AssertSuccess()
	})
}

func enrollRejectsInvalidTotp(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		name := "test_mfa_verify_invalid_totp"
		added := testutil.FetchAndEnrollJwt(t, state.overlay, state.zetClient, name)
		state.zetClient.WaitForControllerEvent(t, "connected", name)

		enableResp := state.zetClient.EnableMFA(t, added.Id.Identifier)
		enableResp.AssertSuccess()

		verifyResp := state.zetClient.VerifyMFA(t, added.Id.Identifier, "000000")
		verifyResp.AssertFail(500, "the token provided was invalid")
	})
}

func reauthAcceptsValidTotp(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		idName := "test_mfa_reauth_valid_totp"
		enrollment, secret := testutil.EnrollAndVerifyMFA(t, state.overlay, state.zetClient, idName)

		state.zetClient.DisableEnableIdentity(t, enrollment.Identifier)

		state.zetClient.WaitForMfaEvent(t, "auth_challenge", idName)

		code := testutil.GenerateTOTP(t, secret, time.Now())

		submitResp := state.zetClient.SubmitMFA(t, enrollment.Identifier, code)
		submitResp.AssertSuccess()

		updatedEvent := state.zetClient.WaitForIdentityEvent(t, "updated", idName)
		updatedEvent.AssertMfaAuthenticated()

		authStatusEvent := state.zetClient.WaitForMfaEvent(t, "mfa_auth_status", idName)
		authStatusEvent.AssertSuccess()
	})
}

func reauthAcceptsRecoveryCode(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		idName := "test_mfa_reauth_recovery_code"
		enrollment, _ := testutil.EnrollAndVerifyMFA(t, state.overlay, state.zetClient, idName)

		state.zetClient.DisableEnableIdentity(t, enrollment.Identifier)

		state.zetClient.WaitForMfaEvent(t, "auth_challenge", idName)

		submitResp := state.zetClient.SubmitMFA(t, enrollment.Identifier, enrollment.RecoveryCodes[0])
		submitResp.AssertSuccess()

		updatedEvent := state.zetClient.WaitForIdentityEvent(t, "updated", idName)
		updatedEvent.AssertMfaAuthenticated()

		authStatusEvent := state.zetClient.WaitForMfaEvent(t, "mfa_auth_status", idName)
		authStatusEvent.AssertSuccess()
	})
}

func reauthRejectsRecoveryCodeReuse(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		idName := "test_mfa_reauth_reused_recovery_code"
		enrollment, _ := testutil.EnrollAndVerifyMFA(t, state.overlay, state.zetClient, idName)
		recoveryCode := enrollment.RecoveryCodes[0]

		state.zetClient.DisableEnableIdentity(t, enrollment.Identifier)
		state.zetClient.WaitForMfaEvent(t, "auth_challenge", idName)

		firstResp := state.zetClient.SubmitMFA(t, enrollment.Identifier, recoveryCode)
		firstResp.AssertSuccess()

		updatedEvent := state.zetClient.WaitForIdentityEvent(t, "updated", idName)
		updatedEvent.AssertMfaAuthenticated()

		state.zetClient.DisableEnableIdentity(t, enrollment.Identifier)
		state.zetClient.WaitForMfaEvent(t, "auth_challenge", idName)

		reuseResp := state.zetClient.SubmitMFA(t, enrollment.Identifier, recoveryCode)
		reuseResp.AssertFail(500, "the token provided was invalid")
	})
}

func reauthRejectsInvalidTotp(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		idName := "test_mfa_reauth_invalid_totp"
		enrollment, _ := testutil.EnrollAndVerifyMFA(t, state.overlay, state.zetClient, idName)

		state.zetClient.DisableEnableIdentity(t, enrollment.Identifier)

		state.zetClient.WaitForMfaEvent(t, "auth_challenge", idName)

		submitResp := state.zetClient.SubmitMFA(t, enrollment.Identifier, "000000")
		submitResp.AssertFail(500, "the token provided was invalid")
	})
}

func removeAcceptsValidTotp(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		idName := "test_mfa_remove_valid_totp"
		enrollment, secret := testutil.EnrollAndVerifyMFA(t, state.overlay, state.zetClient, idName)

		code := testutil.GenerateTOTP(t, secret, time.Now())

		removeResp := state.zetClient.RemoveMFA(t, enrollment.Identifier, code)
		removeResp.AssertSuccess()

		removeEvent := state.zetClient.WaitForMfaEvent(t, "enrollment_remove", idName)
		removeEvent.AssertSuccess()
	})
}

func removeAcceptsRecoveryCode(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		idName := "test_mfa_remove_recovery_code"
		enrollment, _ := testutil.EnrollAndVerifyMFA(t, state.overlay, state.zetClient, idName)

		removeResp := state.zetClient.RemoveMFA(t, enrollment.Identifier, enrollment.RecoveryCodes[0])
		removeResp.AssertSuccess()

		removeEvent := state.zetClient.WaitForMfaEvent(t, "enrollment_remove", idName)
		removeEvent.AssertSuccess()
	})
}

func removeRejectsInvalidTotp(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		enrollment, _ := testutil.EnrollAndVerifyMFA(t, state.overlay, state.zetClient, "test_mfa_remove_invalid_totp")

		removeResp := state.zetClient.RemoveMFA(t, enrollment.Identifier, "000000")
		removeResp.AssertFail(500, "the token provided was invalid")
	})
}

func recoveryRejectsOldCodeAfterRegeneration(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		idName := "test_mfa_regenerate_codes"
		enrollment, secret := testutil.EnrollAndVerifyMFA(t, state.overlay, state.zetClient, idName)
		oldCode := enrollment.RecoveryCodes[0]

		code := testutil.GenerateTOTP(t, secret, time.Now())
		genResp := state.zetClient.GenerateMFACodes(t, enrollment.Identifier, code)
		genResp.AssertSuccess()

		state.zetClient.DisableEnableIdentity(t, enrollment.Identifier)
		state.zetClient.WaitForMfaEvent(t, "auth_challenge", idName)

		reuseResp := state.zetClient.SubmitMFA(t, enrollment.Identifier, oldCode)
		reuseResp.AssertFail(500, "the token provided was invalid")
	})
}
