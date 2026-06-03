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
	"os"
	"testing"

	"github.com/openziti/ziti-tunnel-sdk-c/tests/integration/testutil"
	"github.com/stretchr/testify/require"
)

func TestRemoveIdentity(t *testing.T) {
	t.Run("withIdentifierFromEvent", testRemoveIdentityWithIdentifierFromEvent)
}

func testRemoveIdentityWithIdentifierFromEvent(t *testing.T) {
	testutil.RunTestWithTimeout(t, func(t *testing.T) {
		client := state.zetClient.Commands

		event := testutil.EnrollImportedJwt(t, state.overlay, state.zetClient, testutil.IdentityName(t))

		t.Logf("sending RemoveIdentity for Identifier=%s", event.Id.Identifier)
		removeResp, err := client.RemoveIdentity(event.Id.Identifier)
		require.NoError(t, err, "failed to send RemoveIdentity\n%s", state.zetClient.LogPath())
		require.True(t, removeResp.Success(), "RemoveIdentity failed: error=%q code=%d", removeResp.Error, removeResp.Code)

		_, statErr := os.Stat(event.Id.Identifier)
		require.True(t, os.IsNotExist(statErr), "identity file should be removed after RemoveIdentity: %s\n%s", event.Id.Identifier, state.zetClient.LogPath())
	})
}
