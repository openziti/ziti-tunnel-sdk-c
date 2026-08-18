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

// How an auth policy that requires TOTP drives the client, both when the identity starts out
// under it and when an administrator moves the identity onto it later. See docs/totp.md for
// the states these cover.

package integration_test

import (
	"testing"
	"time"

	"github.com/openziti/ziti-tunnel-sdk-c/tests/integration/testutil"
	"github.com/stretchr/testify/require"
)

const totpRequiredPolicy = "test_mfa_totp_policy"

func TestMFAAuthPolicy(t *testing.T) {
	t.Run("reauthUnderTotpRequiredPolicyAsksForCode", reauthUnderTotpRequiredPolicyAsksForCode)
	t.Run("policyAddedForEnrolledIdentityKeepsWorking", policyAddedForEnrolledIdentityKeepsWorking)
	t.Run("policyAddedForUnenrolledIdentityAsksToEnroll", policyAddedForUnenrolledIdentityAsksToEnroll)
}

// An identity whose auth policy requires TOTP, already enrolled, authenticating again.
//
// The existing enrollment coverage stops at verification, so nothing re-authenticates an
// identity under this policy. A code is what it must be asked for - the policy requiring TOTP
// must not produce an enrollment request for an identity that has already enrolled.
func reauthUnderTotpRequiredPolicyAsksForCode(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		// getting this identity enrolled at all needs openziti/ziti#3496, which landed in ziti
		// 2.0 for the OIDC path only. The legacy api-session path still refuses to enroll TOTP
		// from a partially authenticated session, whatever the controller version, so the
		// version alone does not decide this.
		if state.overlay.ZitiMajor < 2 {
			t.Skipf("MFA enrollment under a TOTP-required auth policy needs ziti 2.0+; controller is v%d.%d (openziti/ziti#3496)",
				state.overlay.ZitiMajor, state.overlay.ZitiMinor)
		}
		state.overlay.RequireOidcAuth(t)

		idName := "test_mfa_policy_required_enrolled"
		identifier, secret := enrollUnderTotpRequiredPolicy(t, idName)

		state.zetClient.DisableEnableIdentity(t, identifier)

		state.zetClient.WaitForMfaEvent(t, "auth_challenge", idName)
		state.zetClient.AssertNoMfaEvent(t, "enrollment_required", idName, time.Second)

		code := testutil.GenerateTOTP(t, secret, time.Now())
		state.zetClient.SubmitMFA(t, identifier, code).AssertSuccess()
		state.zetClient.WaitForIdentityEvent(t, "updated", idName).AssertMfaAuthenticated()
	})
}

// An authenticated, enrolled identity that an administrator moves onto a policy requiring
// TOTP. Its session already satisfies the new requirement, so nothing should change.
func policyAddedForEnrolledIdentityKeepsWorking(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		idName := "test_mfa_policy_added_enrolled"
		enrollment, _ := testutil.EnrollAndVerifyMFA(t, state.overlay, state.zetClient, idName)

		state.overlay.SetIdentityAuthPolicy(t, idName, totpRequiredPolicy)
		state.zetClient.RefreshIdentity(t, enrollment.Identifier).AssertSuccess()

		state.zetClient.AssertNoMfaEvent(t, "auth_challenge", idName, 2*time.Second)
		state.zetClient.AssertNoMfaEvent(t, "enrollment_required", idName, time.Second)

		state.zetClient.ReconnectEvents(t)
		identity := findIdentityInStatus(t, state.zetClient.WaitForStatusEvent(t), enrollment.Identifier)
		require.True(t, identity.MfaEnabled, "status says MfaEnabled=false for enrolled identity %q", idName)
		require.False(t, identity.MfaNeeded, "status says MfaNeeded=true for %q, whose session already satisfies TOTP", idName)
	})
}

// An authenticated identity with no TOTP enrollment that an administrator moves onto a policy
// requiring TOTP. It can no longer satisfy the policy, so the client has to say so: MfaNeeded
// goes true and the user is asked to enroll.
func policyAddedForUnenrolledIdentityAsksToEnroll(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		idName := "test_mfa_policy_added_unenrolled"
		added := testutil.FetchAndEnrollJwt(t, state.overlay, state.zetClient, idName)
		state.zetClient.WaitForControllerEvent(t, "connected", idName)

		state.overlay.SetIdentityAuthPolicy(t, idName, totpRequiredPolicy)
		state.zetClient.DisableEnableIdentity(t, added.Id.Identifier)

		state.zetClient.WaitForMfaEvent(t, "enrollment_required", idName)
		state.zetClient.AssertNoMfaEvent(t, "auth_challenge", idName, time.Second)

		state.zetClient.ReconnectEvents(t)
		identity := findIdentityInStatus(t, state.zetClient.WaitForStatusEvent(t), added.Id.Identifier)
		require.False(t, identity.MfaEnabled, "status says MfaEnabled=true for %q, which never enrolled", idName)
		require.True(t, identity.MfaNeeded, "status says MfaNeeded=false for %q, which cannot satisfy its new policy", idName)
	})
}

// enrollUnderTotpRequiredPolicy adds a pre-imported identity whose auth policy requires TOTP
// and completes its enrollment, returning the tunneler's identifier for it and its secret.
//
// EnrollAndVerifyMFA does not work here: it waits for the controller "connected" event, which
// never arrives while TOTP is required and unenrolled. The identity stays partially
// authenticated and the first thing it hears is an enrollment request.
func enrollUnderTotpRequiredPolicy(t *testing.T, idName string) (string, string) {
	jwt := state.overlay.GetJwtFromController(t, idName)
	state.zetClient.AddIdentity(t, testutil.NewJwtIdentityData(idName, jwt)).AssertSuccess()

	enrollmentRequired := state.zetClient.WaitForMfaEvent(t, "enrollment_required", idName)

	enableResp := state.zetClient.EnableMFA(t, enrollmentRequired.Identifier)
	enableResp.AssertSuccess()
	require.NotEmpty(t, enableResp.Data.ProvisioningUrl, "EnableMFA Data.ProvisioningUrl should be non-empty")

	state.zetClient.WaitForMfaEvent(t, "enrollment_challenge", idName).AssertSuccess()

	secret := testutil.ParseTOTPSecret(t, enableResp.Data.ProvisioningUrl)
	code := testutil.GenerateTOTP(t, secret, time.Now())
	state.zetClient.VerifyMFA(t, enrollmentRequired.Identifier, code).AssertSuccess()

	state.zetClient.WaitForIdentityEvent(t, "updated", idName).AssertMfaAuthenticated()
	state.zetClient.WaitForMfaEvent(t, "enrollment_verification", idName).AssertSuccess()

	return enrollmentRequired.Identifier, secret
}
