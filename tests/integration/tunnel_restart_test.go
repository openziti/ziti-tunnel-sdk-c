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

	c.overlay.RequireCATrusted(t)
	c.idp.RequireConfigured(t)
	testutil.SetupWorkingExtJwtSigner(t, c.overlay, c.idp)

	testutil.RunTestWithTimeoutOf(t, restartTestTimeout, func(t *testing.T) {
		// One identity per state. To exercise a single case, comment out its
		// enroll block here and its matching asserts below.
		base := testutil.IdentityName(t)

		jwtName := base + "-jwt"
		jwtEvent := testutil.EnrollJwtIdentity(t, c.overlay, c.zet, jwtName)
		c.zet.Events.WaitForControllerEvent(t, "connected", jwtName)

		mfaName := base + "-mfa"
		mfaEnrollment, _ := testutil.SetupVerifiedMFA(t, c.overlay, c.zet, mfaName)

		inactiveName := base + "-inactive"
		inactiveEvent := testutil.EnrollJwtIdentity(t, c.overlay, c.zet, inactiveName)
		c.zet.Events.WaitForControllerEvent(t, "connected", inactiveName)
		testutil.SetIdentityActive(t, c.zet, inactiveEvent.Id.Identifier, false)

		extName := base + "-ext"
		c.overlay.CreateIdentityWithExternalId(t, extName, c.idp.ExternalID, "")
		extEvent := testutil.EnrollUrlIdentityToNone(t, c.overlay, c.zet, extName)

		t.Logf("restarting zetC")
		require.NoError(t, c.zet.Restart(), "restart zetC\n%s", c.zet.LogPath())

		// After restart every identity must still report its enrolled state.
		after := c.zet.Events.WaitForStatusEvent(t)
		c.assertValidJwtIdState(t, findIdentityInStatus(t, after, jwtEvent.Id.Identifier))
		c.assertValidMfaIdState(t, findIdentityInStatus(t, after, mfaEnrollment.Identifier))
		c.assertValidInactiveIdState(t, findIdentityInStatus(t, after, inactiveEvent.Id.Identifier))

		// ext-auth reloads unevaluated: the first post-restart status reports
		// NeedsExtAuth=false, then needs_ext_login fires; reconnecting observes the
		// settled NeedsExtAuth=true.
		reloaded := findIdentityInStatus(t, after, extEvent.Id.Identifier)
		require.False(t, reloaded.NeedsExtAuth, "post-restart status NeedsExtAuth=true before needs_ext_login for %q", extName)
		t.Logf("post-restart status reports NeedsExtAuth=%t for %q", reloaded.NeedsExtAuth, extName)
		c.zet.Events.WaitForIdentityEvent(t, "needs_ext_login", extName)
		c.zet.ReconnectEvents(t)
		reconnect := c.zet.Events.WaitForStatusEvent(t)
		c.assertValidExtAuthIdState(t, findIdentityInStatus(t, reconnect, extEvent.Id.Identifier))
	})
}

func (c *restartContext) assertValidJwtIdState(t *testing.T, identity testutil.Identity) {
	require.NotEmpty(t, identity.Identifier, "identity Identifier empty")
	require.False(t, identity.NeedsExtAuth, "NeedsExtAuth=%t for jwt identity %q", identity.NeedsExtAuth, identity.Name)
	require.False(t, identity.MfaNeeded, "MfaNeeded=%t for jwt identity %q", identity.MfaNeeded, identity.Name)
	testutil.AssertValidJwtEnrolledIdentityFile(t, identity.Identifier)
	t.Logf("identity %q present NeedsExtAuth=%t MfaNeeded=%t", identity.Name, identity.NeedsExtAuth, identity.MfaNeeded)
}

func (c *restartContext) assertValidMfaIdState(t *testing.T, identity testutil.Identity) {
	require.NotEmpty(t, identity.Identifier, "identity Identifier empty")
	require.True(t, identity.MfaEnabled, "MfaEnabled=%t for mfa identity %q", identity.MfaEnabled, identity.Name)
	testutil.AssertValidJwtEnrolledIdentityFile(t, identity.Identifier)
	t.Logf("identity %q present MfaEnabled=%t MfaNeeded=%t", identity.Name, identity.MfaEnabled, identity.MfaNeeded)
}

func (c *restartContext) assertValidInactiveIdState(t *testing.T, identity testutil.Identity) {
	require.NotEmpty(t, identity.Identifier, "identity Identifier empty")
	require.False(t, identity.Active, "Active=%t for inactive identity %q", identity.Active, identity.Name)
	testutil.AssertValidJwtEnrolledIdentityFile(t, identity.Identifier)
	t.Logf("identity %q present Active=%t", identity.Name, identity.Active)
}

func (c *restartContext) assertValidExtAuthIdState(t *testing.T, identity testutil.Identity) {
	require.NotEmpty(t, identity.Identifier, "identity Identifier empty")
	require.True(t, identity.NeedsExtAuth, "NeedsExtAuth=%t for ext-auth identity %q", identity.NeedsExtAuth, identity.Name)
	testutil.AssertValidUrlEnrolledIdentityFile(t, identity.Identifier, testutil.EnrollModeNone)
	t.Logf("identity %q present NeedsExtAuth=%t", identity.Name, identity.NeedsExtAuth)
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
