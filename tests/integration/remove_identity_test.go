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
	"context"
	"os"
	"testing"
	"time"

	"github.com/openziti/ziti-tunnel-sdk-c/tests/integration/testutil"
	"github.com/stretchr/testify/require"
)

func TestRemoveIdentity(t *testing.T) {
	t.Run("withIdentifierFromEvent", testRemoveIdentityWithIdentifierFromEvent)
}

func testRemoveIdentityWithIdentifierFromEvent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	overlay := state.overlay
	client := state.zetClient.Commands
	events := state.zetClient.Events

	name := testutil.IdentityName(t)

	t.Logf("creating JWT for %q", name)
	jwt, err := overlay.CreateIdentityJWT(ctx, name)
	require.NoError(t, err, "failed to create JWT")
	require.NotEmpty(t, jwt)

	identityData := testutil.AddIdentityData{
		IdentityFilename: name,
		JwtContent:       &jwt,
	}
	addResp := testutil.AddIdentity(t, ctx, client, identityData)
	require.True(t, addResp.Success, "AddIdentity failed: error=%q code=%d", addResp.Error, addResp.Code)

	event := events.WaitFor(t, ctx, "identity", "added", name)
	require.NotEmpty(t, event.Id.Identifier, "identity:added Identifier empty")
	testutil.AssertValidJwtEnrolledIdentityFile(t, event.Id.Identifier)

	t.Logf("sending RemoveIdentity for Identifier=%s", event.Id.Identifier)
	removeResp, err := client.RemoveIdentity(ctx, event.Id.Identifier)
	require.NoError(t, err, "failed to send RemoveIdentity\n%s", state.zetClient.LogPath())
	require.True(t, removeResp.Success, "RemoveIdentity failed: error=%q code=%d", removeResp.Error, removeResp.Code)
	t.Logf("RemoveIdentity succeeded for %q", name)

	_, statErr := os.Stat(event.Id.Identifier)
	require.True(t, os.IsNotExist(statErr), "identity file should be removed after RemoveIdentity: %s\n%s", event.Id.Identifier, state.zetClient.LogPath())
	t.Logf("identity file removed from disk: %s", event.Id.Identifier)
}
