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

	"github.com/openziti/ziti-tunnel-sdk-c/tests/integration/testutil"
	"github.com/stretchr/testify/require"
)

func TestIdentityOnOff(t *testing.T) {
	t.Run("togglesActiveOff", testIdentityOnOffTogglesActiveOff)
	t.Run("togglesActiveOn", testIdentityOnOffTogglesActiveOn)
}

func testIdentityOnOffTogglesActiveOff(t *testing.T) {
	testutil.RunTestWithTimeout(t, func(t *testing.T) {
		client := state.zetClient.Commands
		events := state.zetClient.Events

		name := testutil.IdentityName(t)
		added := testutil.CreateAndEnrollJwt(t, state.overlay, state.zetClient, name)

		t.Logf("sending IdentityOnOff(false) for %q", name)
		offResp, err := client.IdentityOnOff(added.Id.Identifier, false)
		require.NoError(t, err, "failed to send IdentityOnOff(false)\n%s", state.zetClient.LogPath())
		require.True(t, offResp.Success(), "IdentityOnOff(false) failed: error=%q code=%d", offResp.Error, offResp.Code)

		off := events.WaitForIdentityEvent(t, "added", name)
		require.False(t, off.Id.Active, "identity:added Active=%t after IdentityOnOff(false)", off.Id.Active)
	})
}

func testIdentityOnOffTogglesActiveOn(t *testing.T) {
	testutil.RunTestWithTimeout(t, func(t *testing.T) {
		client := state.zetClient.Commands
		events := state.zetClient.Events

		name := testutil.IdentityName(t)
		added := testutil.CreateAndEnrollJwt(t, state.overlay, state.zetClient, name)

		t.Logf("sending IdentityOnOff(false) for %q", name)
		offResp, err := client.IdentityOnOff(added.Id.Identifier, false)
		require.NoError(t, err, "failed to send IdentityOnOff(false)\n%s", state.zetClient.LogPath())
		require.True(t, offResp.Success(), "IdentityOnOff(false) failed: error=%q code=%d", offResp.Error, offResp.Code)

		off := events.WaitForIdentityEvent(t, "added", name)
		require.False(t, off.Id.Active, "identity:added Active=%t after IdentityOnOff(false)", off.Id.Active)

		t.Logf("sending IdentityOnOff(true) for %q", name)
		onResp, err := client.IdentityOnOff(added.Id.Identifier, true)
		require.NoError(t, err, "failed to send IdentityOnOff(true)\n%s", state.zetClient.LogPath())
		require.True(t, onResp.Success(), "IdentityOnOff(true) failed: error=%q code=%d", onResp.Error, onResp.Code)

		on := events.WaitForIdentityEvent(t, "added", name)
		require.True(t, on.Id.Active, "identity:added Active=%t after IdentityOnOff(true)", on.Id.Active)
	})
}
