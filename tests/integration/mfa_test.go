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

type mfaContext struct {
	overlay *testutil.Overlay
	zet     *testutil.ZET
}

func newMfaContext() *mfaContext {
	return &mfaContext{
		overlay: state.overlay,
		zet:     state.zetClient,
	}
}

func TestEnableMFA(t *testing.T) {
	c := newMfaContext()
	t.Run("acceptsJwtEnrolledIdentity", c.acceptsJwtEnrolledIdentity)
	t.Run("acceptsTotpRequiredAuthPolicy", c.acceptsTotpRequiredAuthPolicy)
}

func TestVerifyMFA(t *testing.T) {
	c := newMfaContext()
	t.Run("acceptsValidTotp", c.verifyAcceptsValidTotp)
	t.Run("rejectsInvalidTotp", c.verifyRejectsInvalidTotp)
}

func TestMFAReauthentication(t *testing.T) {
	c := newMfaContext()
	t.Run("acceptsValidTotp", c.reauthAcceptsValidTotp)
	t.Run("acceptsRecoveryCode", c.reauthAcceptsRecoveryCode)
	t.Run("rejectsInvalidTotp", c.reauthRejectsInvalidTotp)
}

func TestRemoveMFA(t *testing.T) {
	c := newMfaContext()
	t.Run("acceptsValidTotp", c.removeAcceptsValidTotp)
	t.Run("acceptsRecoveryCode", c.removeAcceptsRecoveryCode)
	t.Run("rejectsInvalidTotp", c.removeRejectsInvalidTotp)
}

func (c *mfaContext) acceptsJwtEnrolledIdentity(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		enrollment, _ := testutil.SetupMFA(t, c.overlay, c.zet, testutil.IdentityName(t))

		require.False(t, enrollment.IsVerified, "EnableMFA Data.IsVerified should be false before verify_mfa")
	})
}

func (c *mfaContext) acceptsTotpRequiredAuthPolicy(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		t.Skip("Tracking https://github.com/openziti/desktop-edge-win/issues/947 and https://openziti.discourse.group/t/enrolling-mfa-totp-from-zdew-fails/5482 - EnableMFA fails with 'failed to authenticate' for identities bound to TOTP-required auth policies")

		enrollment, _ := testutil.SetupMFA(t, c.overlay, c.zet, testutil.IdentityName(t))

		require.False(t, enrollment.IsVerified, "EnableMFA Data.IsVerified should be false before verify_mfa")
	})
}

func (c *mfaContext) verifyAcceptsValidTotp(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		testutil.SetupVerifiedMFA(t, c.overlay, c.zet, testutil.IdentityName(t))
	})
}

func (c *mfaContext) verifyRejectsInvalidTotp(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		name := testutil.IdentityName(t)
		enrollment, _ := testutil.SetupMFA(t, c.overlay, c.zet, name)

		t.Logf("sending VerifyMFA with invalid TOTP for %q", name)
		verifyResp, err := c.zet.VerifyMFA(enrollment.Identifier, "000000")
		require.NoError(t, err, "failed to send VerifyMFA\n%s", c.zet.LogPath())
		require.False(t, verifyResp.Success(), "VerifyMFA with invalid TOTP should fail but Success=true")
		require.Equal(t, 500, verifyResp.Code, "expected Code=500, got %d", verifyResp.Code)
		require.Contains(t, verifyResp.Error, "the token provided was invalid", "expected invalid-token error, got %q", verifyResp.Error)
	})
}

func (c *mfaContext) reauthAcceptsValidTotp(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		name := testutil.IdentityName(t)
		enrollment, secret := testutil.SetupVerifiedMFA(t, c.overlay, c.zet, name)

		testutil.SetIdentityActive(t, c.zet, enrollment.Identifier, false)
		testutil.SetIdentityActive(t, c.zet, enrollment.Identifier, true)

		c.zet.WaitForMfaEvent(t, "auth_challenge", name)

		code, err := testutil.GenerateTOTP(secret, time.Now())
		require.NoError(t, err, "failed to compute TOTP")

		t.Logf("sending SubmitMFA with valid TOTP for %q", name)
		submitResp, err := c.zet.SubmitMFA(enrollment.Identifier, code)
		require.NoError(t, err, "failed to send SubmitMFA\n%s", c.zet.LogPath())
		require.True(t, submitResp.Success(), "SubmitMFA failed: error=%q code=%d\n%s", submitResp.Error, submitResp.Code, c.zet.LogPath())

		submitEvt := c.zet.WaitForMfaEvent(t, "mfa_auth_status", name)
		require.True(t, submitEvt.Successful, "mfa:mfa_auth_status Successful=%t after SubmitMFA", submitEvt.Successful)
	})
}

func (c *mfaContext) reauthAcceptsRecoveryCode(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		name := testutil.IdentityName(t)
		enrollment, _ := testutil.SetupVerifiedMFA(t, c.overlay, c.zet, name)

		testutil.SetIdentityActive(t, c.zet, enrollment.Identifier, false)
		testutil.SetIdentityActive(t, c.zet, enrollment.Identifier, true)

		c.zet.WaitForMfaEvent(t, "auth_challenge", name)

		t.Logf("sending SubmitMFA with recovery code for %q", name)
		submitResp, err := c.zet.SubmitMFA(enrollment.Identifier, enrollment.RecoveryCodes[0])
		require.NoError(t, err, "failed to send SubmitMFA\n%s", c.zet.LogPath())
		require.True(t, submitResp.Success(), "SubmitMFA failed: error=%q code=%d\n%s", submitResp.Error, submitResp.Code, c.zet.LogPath())

		submitEvt := c.zet.WaitForMfaEvent(t, "mfa_auth_status", name)
		require.True(t, submitEvt.Successful, "mfa:mfa_auth_status Successful=%t after SubmitMFA", submitEvt.Successful)
	})
}

func (c *mfaContext) reauthRejectsInvalidTotp(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		name := testutil.IdentityName(t)
		enrollment, _ := testutil.SetupVerifiedMFA(t, c.overlay, c.zet, name)

		testutil.SetIdentityActive(t, c.zet, enrollment.Identifier, false)
		testutil.SetIdentityActive(t, c.zet, enrollment.Identifier, true)

		c.zet.WaitForMfaEvent(t, "auth_challenge", name)

		t.Logf("sending SubmitMFA with invalid TOTP for %q", name)
		submitResp, err := c.zet.SubmitMFA(enrollment.Identifier, "000000")
		require.NoError(t, err, "failed to send SubmitMFA\n%s", c.zet.LogPath())
		require.False(t, submitResp.Success(), "SubmitMFA with invalid TOTP should fail but Success=true")
		require.Equal(t, 500, submitResp.Code, "expected Code=500, got %d", submitResp.Code)
		require.Contains(t, submitResp.Error, "the token provided was invalid", "expected invalid-token error, got %q", submitResp.Error)
	})
}

func (c *mfaContext) removeAcceptsValidTotp(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		name := testutil.IdentityName(t)
		enrollment, secret := testutil.SetupVerifiedMFA(t, c.overlay, c.zet, name)

		code, err := testutil.GenerateTOTP(secret, time.Now())
		require.NoError(t, err, "failed to compute TOTP")

		t.Logf("sending RemoveMFA with valid TOTP for %q", name)
		removeResp, err := c.zet.RemoveMFA(enrollment.Identifier, code)
		require.NoError(t, err, "failed to send RemoveMFA\n%s", c.zet.LogPath())
		require.True(t, removeResp.Success(), "RemoveMFA failed: error=%q code=%d\n%s", removeResp.Error, removeResp.Code, c.zet.LogPath())

		removeEvt := c.zet.WaitForMfaEvent(t, "enrollment_remove", name)
		require.True(t, removeEvt.Successful, "mfa:enrollment_remove Successful=%t after RemoveMFA", removeEvt.Successful)
	})
}

func (c *mfaContext) removeAcceptsRecoveryCode(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		name := testutil.IdentityName(t)
		enrollment, _ := testutil.SetupVerifiedMFA(t, c.overlay, c.zet, name)

		t.Logf("sending RemoveMFA with recovery code for %q", name)
		removeResp, err := c.zet.RemoveMFA(enrollment.Identifier, enrollment.RecoveryCodes[0])
		require.NoError(t, err, "failed to send RemoveMFA\n%s", c.zet.LogPath())
		require.True(t, removeResp.Success(), "RemoveMFA failed: error=%q code=%d\n%s", removeResp.Error, removeResp.Code, c.zet.LogPath())

		removeEvt := c.zet.WaitForMfaEvent(t, "enrollment_remove", name)
		require.True(t, removeEvt.Successful, "mfa:enrollment_remove Successful=%t after RemoveMFA", removeEvt.Successful)
	})
}

func (c *mfaContext) removeRejectsInvalidTotp(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		name := testutil.IdentityName(t)
		enrollment, _ := testutil.SetupVerifiedMFA(t, c.overlay, c.zet, name)

		t.Logf("sending RemoveMFA with invalid TOTP for %q", name)
		removeResp, err := c.zet.RemoveMFA(enrollment.Identifier, "000000")
		require.NoError(t, err, "failed to send RemoveMFA\n%s", c.zet.LogPath())
		require.False(t, removeResp.Success(), "RemoveMFA with invalid TOTP should fail but Success=true")
		require.Equal(t, 500, removeResp.Code, "expected Code=500, got %d", removeResp.Code)
		require.Contains(t, removeResp.Error, "the token provided was invalid", "expected invalid-token error, got %q", removeResp.Error)
	})
}
