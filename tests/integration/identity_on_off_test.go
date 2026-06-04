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
	t.Run("togglesActiveState", togglesActiveState)
}

func togglesActiveState(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		client := state.zetClient.CommandsClient
		events := state.zetClient.EventClient

		name := testutil.IdentityName(t)
		added := testutil.FetchAndEnrollJwt(t, state.overlay, state.zetClient, name)

		client.IdentityOnOff(t, added.Id.Identifier, false).AssertSuccess(t)

		off := events.WaitForIdentityEvent(t, "added", name)
		require.False(t, off.Id.Active, "identity:added Active=%t after IdentityOnOff(false)", off.Id.Active)

		client.IdentityOnOff(t, added.Id.Identifier, true).AssertSuccess(t)

		on := events.WaitForIdentityEvent(t, "added", name)
		require.True(t, on.Id.Active, "identity:added Active=%t after IdentityOnOff(true)", on.Id.Active)
	})
}
