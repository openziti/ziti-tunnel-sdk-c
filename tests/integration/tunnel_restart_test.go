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

func TestTunnelRestart(t *testing.T) {
	state.overlay.RequireCATrusted(t)
	state.idp.RequireConfigured(t)
	testutil.SetupWorkingExtJwtSigner(t, state.overlay, state.idp)

	testutil.RunWithTimeoutOf(t, restartTestTimeout, func(t *testing.T) {
		// One identity per state. To exercise a single case, comment out its
		// enroll block here and its matching asserts below.
		jwtIdName := "test_restart_jwt"
		jwtIdEvent := testutil.FetchAndEnrollJwt(t, state.overlay, state.zetClient, jwtIdName)
		state.zetClient.WaitForControllerEvent(t, "connected", jwtIdName)

		mfaEnrollment, _ := testutil.EnrollAndVerifyMFA(t, state.overlay, state.zetClient, "test_restart_mfa")

		inactiveIdName := "test_restart_inactive"
		inactiveIdEvent := testutil.FetchAndEnrollJwt(t, state.overlay, state.zetClient, inactiveIdName)
		state.zetClient.WaitForControllerEvent(t, "connected", inactiveIdName)
		offResp := state.zetClient.IdentityOnOff(t, inactiveIdEvent.Id.Identifier, false)
		offResp.AssertSuccess()

		extName := "test_restart_ext"
		extEvent := testutil.EnrollUrlIdentityToNone(t, state.overlay, state.zetClient, extName)

		t.Logf("restarting %s", state.zetClient.Discriminator)
		require.NoError(t, state.zetClient.Restart(), "restart %s\n%s", state.zetClient.Discriminator, state.zetClient.LogPath())

		// After restart every identity must still report its enrolled state.
		after := state.zetClient.WaitForStatusEvent(t)
		assertValidJwtIdState(t, findIdentityInStatus(t, after, jwtIdEvent.Id.Identifier))
		assertMfaEnabled(t, findIdentityInStatus(t, after, mfaEnrollment.Identifier))
		assertIdInactive(t, findIdentityInStatus(t, after, inactiveIdEvent.Id.Identifier))

		// ext-auth reloads unevaluated: the first post-restart status reports
		// NeedsExtAuth=false, then needs_ext_login fires; reconnecting observes the
		// settled NeedsExtAuth=true.
		reloaded := findIdentityInStatus(t, after, extEvent.Id.Identifier)
		require.False(t, reloaded.NeedsExtAuth, "post-restart status NeedsExtAuth=true before needs_ext_login for %q", extName)
		state.zetClient.WaitForIdentityEvent(t, "needs_ext_login", extName)
		state.zetClient.ReconnectEvents(t)
		reconnect := state.zetClient.WaitForStatusEvent(t)
		assertNeedsExtAuth(t, findIdentityInStatus(t, reconnect, extEvent.Id.Identifier))
	})
}

func assertValidJwtIdState(t *testing.T, identity testutil.Identity) {
	require.NotEmpty(t, identity.Identifier, "identity Identifier empty")
	require.False(t, identity.NeedsExtAuth, "NeedsExtAuth=%t for jwt identity %q", identity.NeedsExtAuth, identity.Name)
	require.False(t, identity.MfaNeeded, "MfaNeeded=%t for jwt identity %q", identity.MfaNeeded, identity.Name)
	testutil.AssertValidJwtEnrolledIdentityFile(t, identity.Identifier)
}

func assertMfaEnabled(t *testing.T, identity testutil.Identity) {
	require.NotEmpty(t, identity.Identifier, "identity Identifier empty")
	require.True(t, identity.MfaEnabled, "MfaEnabled=%t for mfa identity %q", identity.MfaEnabled, identity.Name)
	testutil.AssertValidJwtEnrolledIdentityFile(t, identity.Identifier)
}

func assertIdInactive(t *testing.T, identity testutil.Identity) {
	require.NotEmpty(t, identity.Identifier, "identity Identifier empty")
	require.False(t, identity.Active, "Active=%t for inactive identity %q", identity.Active, identity.Name)
	testutil.AssertValidJwtEnrolledIdentityFile(t, identity.Identifier)
}

func assertNeedsExtAuth(t *testing.T, identity testutil.Identity) {
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
