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
		zet:     state.zetClient,
		idp:     state.idp,
	}

	c.overlay.RequireCATrusted(t)
	c.idp.RequireConfigured(t)
	testutil.SetupWorkingExtJwtSigner(t, c.overlay, c.idp)

	testutil.RunWithTimeoutOf(t, restartTestTimeout, func(t *testing.T) {
		// One identity per state. To exercise a single case, comment out its
		// enroll block here and its matching asserts below.
		base := testutil.IdentityName(t)

		jwtIdEvent := testutil.EnrollImportedJwt(t, c.overlay, c.zet, base+"-jwt")
		c.zet.WaitForControllerEvent(t, "connected", base+"-jwt")

		mfaEnrollment, _ := testutil.SetupVerifiedMFA(t, c.overlay, c.zet, base+"-mfa")

		inactiveIdEvent := testutil.EnrollImportedJwt(t, c.overlay, c.zet, base+"-inactive")
		c.zet.WaitForControllerEvent(t, "connected", base+"-inactive")
		testutil.SetIdentityActive(t, c.zet, inactiveIdEvent.Id.Identifier, false)

		extName := base + "-ext"
		c.overlay.CreateIdentityWithExternalId(t, extName, c.idp.ExternalID, "")
		extEvent := testutil.EnrollUrlIdentityToNone(t, c.overlay, c.zet, extName)

		t.Logf("restarting %s", c.zet.Discriminator)
		require.NoError(t, c.zet.Restart(), "restart %s\n%s", c.zet.Discriminator, c.zet.LogPath())

		// After restart every identity must still report its enrolled state.
		after := c.zet.WaitForStatusEvent(t)
		c.assertValidJwtIdState(t, findIdentityInStatus(t, after, jwtIdEvent.Id.Identifier))
		c.assertMfaEnabled(t, findIdentityInStatus(t, after, mfaEnrollment.Identifier))
		c.assertIdInactive(t, findIdentityInStatus(t, after, inactiveIdEvent.Id.Identifier))

		// ext-auth reloads unevaluated: the first post-restart status reports
		// NeedsExtAuth=false, then needs_ext_login fires; reconnecting observes the
		// settled NeedsExtAuth=true.
		reloaded := findIdentityInStatus(t, after, extEvent.Id.Identifier)
		require.False(t, reloaded.NeedsExtAuth, "post-restart status NeedsExtAuth=true before needs_ext_login for %q", extName)
		c.zet.WaitForIdentityEvent(t, "needs_ext_login", extName)
		c.zet.ReconnectEvents(t)
		reconnect := c.zet.WaitForStatusEvent(t)
		c.assertNeedsExtAuth(t, findIdentityInStatus(t, reconnect, extEvent.Id.Identifier))
	})
}

func (c *restartContext) assertValidJwtIdState(t *testing.T, identity testutil.Identity) {
	require.NotEmpty(t, identity.Identifier, "identity Identifier empty")
	require.False(t, identity.NeedsExtAuth, "NeedsExtAuth=%t for jwt identity %q", identity.NeedsExtAuth, identity.Name)
	require.False(t, identity.MfaNeeded, "MfaNeeded=%t for jwt identity %q", identity.MfaNeeded, identity.Name)
	testutil.AssertValidJwtEnrolledIdentityFile(t, identity.Identifier)
}

func (c *restartContext) assertMfaEnabled(t *testing.T, identity testutil.Identity) {
	require.NotEmpty(t, identity.Identifier, "identity Identifier empty")
	require.True(t, identity.MfaEnabled, "MfaEnabled=%t for mfa identity %q", identity.MfaEnabled, identity.Name)
	testutil.AssertValidJwtEnrolledIdentityFile(t, identity.Identifier)
}

func (c *restartContext) assertIdInactive(t *testing.T, identity testutil.Identity) {
	require.NotEmpty(t, identity.Identifier, "identity Identifier empty")
	require.False(t, identity.Active, "Active=%t for inactive identity %q", identity.Active, identity.Name)
	testutil.AssertValidJwtEnrolledIdentityFile(t, identity.Identifier)
}

func (c *restartContext) assertNeedsExtAuth(t *testing.T, identity testutil.Identity) {
	require.NotEmpty(t, identity.Identifier, "identity Identifier empty")
	require.True(t, identity.NeedsExtAuth, "NeedsExtAuth=%t for ext-auth identity %q", identity.NeedsExtAuth, identity.Name)
	testutil.AssertValidUrlEnrolledIdentityFile(t, identity.Identifier, testutil.EnrollModeNone)
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
