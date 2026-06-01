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

const restartTestTimeout = 20 * time.Second

type restartContext struct {
	overlay *testutil.Overlay
	zet     *testutil.ZET
}

func TestTunnelRestart(t *testing.T) {
	c := &restartContext{
		overlay: state.overlay,
		zet:     state.zetC,
	}

	require.NoError(t, c.zet.RemoveJSONIdentities(), "wipe zetC identity dir before first start")
	require.NoError(t, c.zet.Start(), "start zetC")
	t.Cleanup(c.zet.Stop)

	t.Run("testJwtIdentitySurvivesRestart", c.testJwtIdentitySurvivesRestart)
}

func (c *restartContext) testJwtIdentitySurvivesRestart(t *testing.T) {
	testutil.RunTestWithTimeoutOf(t, restartTestTimeout, func(t *testing.T) {
		name := testutil.IdentityName(t)

		identityEvent := c.addJwtIdentity(t, name)
		c.assertJwtIdentity(t, identityEvent.Id)

		t.Logf("restarting zetC")
		require.NoError(t, c.zet.Restart(), "restart zetC\n%s", c.zet.LogPath())

		status := c.zet.Events.WaitForStatusEvent(t)
		identityFromStatus := findIdentityInStatus(t, status, identityEvent.Id.Identifier)
		c.assertJwtIdentity(t, identityFromStatus)
		c.zet.Events.WaitForControllerEvent(t, "connected", name)

		c.removeIdentity(t, identityEvent.Id.Identifier)
	})
}

func (c *restartContext) addJwtIdentity(t *testing.T, name string) testutil.IdentityEvent {
	t.Logf("creating JWT for %q", name)
	jwt, err := c.overlay.CreateIdentityJWT(name)
	require.NoError(t, err, "failed to create JWT")
	require.NotEmpty(t, jwt)

	identityData := testutil.AddIdentityData{
		IdentityFilename: name,
		JwtContent:       &jwt,
	}
	addResp := testutil.AddIdentity(t, c.zet.Commands, identityData)
	require.True(t, addResp.Success(), "AddIdentity failed: error=%q code=%d\n%s", addResp.Error, addResp.Code, c.zet.LogPath())

	identityEvent := c.zet.Events.WaitForIdentityEvent(t, "added", name)
	require.NotEmpty(t, identityEvent.Id.Identifier, "identity:added Identifier empty")
	c.zet.Events.WaitForControllerEvent(t, "connected", name)

	return identityEvent
}

func (c *restartContext) assertJwtIdentity(t *testing.T, identity testutil.Identity) {
	require.NotEmpty(t, identity.Identifier, "identity Identifier empty")
	require.False(t, identity.NeedsExtAuth, "NeedsExtAuth=%t for jwt identity %q", identity.NeedsExtAuth, identity.Name)
	require.False(t, identity.MfaNeeded, "MfaNeeded=%t for jwt identity %q", identity.MfaNeeded, identity.Name)
	testutil.AssertValidJwtEnrolledIdentityFile(t, identity.Identifier)
	t.Logf("identity %q present NeedsExtAuth=%t MfaNeeded=%t", identity.Name, identity.NeedsExtAuth, identity.MfaNeeded)
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
	require.FailNow(t, "identity missing from restart status", "identifier=%s", identifier)
	return testutil.Identity{}
}
