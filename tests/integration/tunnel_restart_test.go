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

const restartTestTimeout = 15 * time.Second

type restartContext struct {
	overlay *testutil.Overlay
	zet     *testutil.ZET
	idp     *testutil.IdP
}

func TestTunnelRestart(t *testing.T) {
	c := &restartContext{
		overlay: state.overlay,
		zet:     state.zetC,
		idp:     state.idp,
	}

	t.Run("testJwtIdentitySurvivesRestart", c.testJwtIdentitySurvivesRestart)
	t.Run("testMfaIdentitySurvivesRestart", c.testMfaIdentitySurvivesRestart)
	t.Run("testExtAuthIdentitySurvivesRestart", c.testExtAuthIdentitySurvivesRestart)
}

func (c *restartContext) testJwtIdentitySurvivesRestart(t *testing.T) {
	testutil.RunTestWithTimeoutOf(t, restartTestTimeout, func(t *testing.T) {
		name := testutil.IdentityName(t)

		identityEvent := testutil.EnrollJwtIdentity(t, c.overlay, c.zet, name)
		c.zet.Events.WaitForControllerEvent(t, "connected", name)

		t.Logf("restarting zetC")
		require.NoError(t, c.zet.Restart(), "restart zetC\n%s", c.zet.LogPath())

		t.Logf("waiting for post-restart status push")
		status := c.zet.Events.WaitForStatusEvent(t)
		identityFromStatus := findIdentityInStatus(t, status, identityEvent.Id.Identifier)
		c.assertJwtIdentity(t, identityFromStatus)

		c.removeIdentity(t, identityEvent.Id.Identifier)
	})
}

func (c *restartContext) assertJwtIdentity(t *testing.T, identity testutil.Identity) {
	require.NotEmpty(t, identity.Identifier, "identity Identifier empty")
	require.False(t, identity.NeedsExtAuth, "NeedsExtAuth=%t for jwt identity %q", identity.NeedsExtAuth, identity.Name)
	require.False(t, identity.MfaNeeded, "MfaNeeded=%t for jwt identity %q", identity.MfaNeeded, identity.Name)
	testutil.AssertValidJwtEnrolledIdentityFile(t, identity.Identifier)
	t.Logf("identity %q present NeedsExtAuth=%t MfaNeeded=%t", identity.Name, identity.NeedsExtAuth, identity.MfaNeeded)
}

func (c *restartContext) testMfaIdentitySurvivesRestart(t *testing.T) {
	testutil.RunTestWithTimeoutOf(t, restartTestTimeout, func(t *testing.T) {
		name := testutil.IdentityName(t)

		identityEvent := c.addMfaIdentity(t, name)

		t.Logf("restarting zetC")
		require.NoError(t, c.zet.Restart(), "restart zetC\n%s", c.zet.LogPath())

		t.Logf("waiting for post-restart status push")
		status := c.zet.Events.WaitForStatusEvent(t)
		identityFromStatus := findIdentityInStatus(t, status, identityEvent.Id.Identifier)
		c.assertMfaIdentity(t, identityFromStatus)

		c.removeIdentity(t, identityEvent.Id.Identifier)
	})
}

func (c *restartContext) addMfaIdentity(t *testing.T, name string) testutil.IdentityEvent {
	identityEvent := testutil.EnrollJwtIdentity(t, c.overlay, c.zet, name)
	c.zet.Events.WaitForControllerEvent(t, "connected", name)
	identifier := identityEvent.Id.Identifier

	t.Logf("enabling MFA for %q", name)
	enrollment, err := c.zet.Commands.GetMFAEnrollment(identifier)
	require.NoError(t, err, "EnableMFA\n%s", c.zet.LogPath())
	require.NotEmpty(t, enrollment.ProvisioningUrl, "EnableMFA ProvisioningUrl empty")

	provisioning, err := url.Parse(enrollment.ProvisioningUrl)
	require.NoError(t, err, "parse provisioning URL %q", enrollment.ProvisioningUrl)
	secret := provisioning.Query().Get("secret")
	require.NotEmpty(t, secret, "provisioning URL missing secret: %q", enrollment.ProvisioningUrl)

	code, err := generateTotpCode(secret, time.Now())
	require.NoError(t, err, "compute TOTP")

	t.Logf("verifying MFA for %q", name)
	verifyResp, err := c.zet.Commands.VerifyMFA(identifier, code)
	require.NoError(t, err, "VerifyMFA\n%s", c.zet.LogPath())
	require.True(t, verifyResp.Success(), "VerifyMFA failed: code=%d error=%q\n%s", verifyResp.Code, verifyResp.Error, c.zet.LogPath())

	verifyEvt := c.zet.Events.WaitForMfaEvent(t, "enrollment_verification", name)
	require.True(t, verifyEvt.Successful, "mfa:enrollment_verification Successful=%t", verifyEvt.Successful)

	return identityEvent
}

func (c *restartContext) assertMfaIdentity(t *testing.T, identity testutil.Identity) {
	require.NotEmpty(t, identity.Identifier, "identity Identifier empty")
	require.True(t, identity.MfaEnabled, "MfaEnabled=%t for mfa identity %q", identity.MfaEnabled, identity.Name)
	testutil.AssertValidJwtEnrolledIdentityFile(t, identity.Identifier)
	t.Logf("identity %q present MfaEnabled=%t MfaNeeded=%t", identity.Name, identity.MfaEnabled, identity.MfaNeeded)
}

func (c *restartContext) testExtAuthIdentitySurvivesRestart(t *testing.T) {
	c.overlay.RequireCATrusted(t)
	c.idp.RequireConfigured(t)
	testutil.SetupWorkingExtJwtSigner(t, c.overlay, c.idp)

	testutil.RunTestWithTimeoutOf(t, restartTestTimeout, func(t *testing.T) {
		name := testutil.IdentityName(t)
		c.overlay.CreateIdentityWithExternalId(t, name, c.idp.ExternalID, "")
		identityEvent := testutil.EnrollUrlIdentityToNone(t, c.overlay, c.zet, name)

		t.Logf("restarting zetC")
		require.NoError(t, c.zet.Restart(), "restart zetC\n%s", c.zet.LogPath())

		// restart reloads the identity unevaluated, so the first status reports
		// NeedsExtAuth=false, then needs_ext_login fires
		initialStatus := c.zet.Events.WaitForStatusEvent(t)
		initial := findIdentityInStatus(t, initialStatus, identityEvent.Id.Identifier)
		require.False(t, initial.NeedsExtAuth, "post-restart status NeedsExtAuth=%t for %q", initial.NeedsExtAuth, name)
		t.Logf("post-restart status reports NeedsExtAuth=%t for %q", initial.NeedsExtAuth, name)
		c.zet.Events.WaitForIdentityEvent(t, "needs_ext_login", name)
		t.Logf("received needs_ext_login for %q", name)

		// reconnecting the IPC pipe to the settled daemon reports NeedsExtAuth=true
		c.zet.ReconnectEvents(t)
		reconnectStatus := c.zet.Events.WaitForStatusEvent(t)
		reloaded := findIdentityInStatus(t, reconnectStatus, identityEvent.Id.Identifier)
		c.assertExtAuthIdentity(t, reloaded)

		c.removeIdentity(t, identityEvent.Id.Identifier)
	})
}

func (c *restartContext) assertExtAuthIdentity(t *testing.T, identity testutil.Identity) {
	require.NotEmpty(t, identity.Identifier, "identity Identifier empty")
	require.True(t, identity.NeedsExtAuth, "NeedsExtAuth=%t for ext-auth identity %q", identity.NeedsExtAuth, identity.Name)
	testutil.AssertValidUrlEnrolledIdentityFile(t, identity.Identifier, testutil.EnrollModeNone)
	t.Logf("identity %q present NeedsExtAuth=%t", identity.Name, identity.NeedsExtAuth)
}

func (c *restartContext) removeIdentity(t *testing.T, identifier string) {
	t.Logf("removing identity %s", identifier)
	resp, err := c.zet.Commands.RemoveIdentity(identifier)
	require.NoError(t, err, "RemoveIdentity\n%s", c.zet.LogPath())
	require.True(t, resp.Success(), "RemoveIdentity failed: code=%d error=%q", resp.Code, resp.Error)
}

func findIdentityInStatus(t *testing.T, status testutil.TunnelStatusEvent, identifier string) testutil.Identity {
	for _, identity := range status.Status.Identities {
		if identity.Identifier == identifier {
			return identity
		}
	}
	require.FailNow(t, "identity missing from status", "identifier=%s", identifier)
	return testutil.Identity{}
}
