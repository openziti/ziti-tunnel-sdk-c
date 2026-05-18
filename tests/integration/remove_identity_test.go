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

	events := testutil.DialEvents(t, ctx, zet)
	client := testutil.DialIPC(t, ctx, zet)

	name := testutil.IdentityName(t)

	t.Logf("minting JWT for %q", name)
	jwt, err := overlay.CreateIdentityJWT(ctx, name)
	require.NoError(t, err, "mint JWT")
	require.NotEmpty(t, jwt)

	identityData := testutil.AddIdentityData{
		IdentityFilename: name,
		JwtContent:       &jwt,
	}
	addResp := testutil.Enroll(t, ctx, client, identityData)
	require.True(t, addResp.Success, "AddIdentity failed: error=%q code=%d", addResp.Error, addResp.Code)

	evt := events.WaitFor(t, ctx, "identity", "added", name)
	require.NotEmpty(t, evt.Id.Identifier, "identity:added Identifier empty")

	t.Logf("sending RemoveIdentity for Identifier=%s", evt.Id.Identifier)
	removeResp, err := client.RemoveIdentity(ctx, evt.Id.Identifier)
	require.NoError(t, err, "RemoveIdentity send\n%s", zet.Logs())
	require.True(t, removeResp.Success, "RemoveIdentity failed: error=%q code=%d", removeResp.Error, removeResp.Code)
	t.Logf("RemoveIdentity succeeded for %q", name)

	_, statErr := os.Stat(evt.Id.Identifier)
	require.True(t, os.IsNotExist(statErr), "identity file should be removed after RemoveIdentity: %s\n%s", evt.Id.Identifier, zet.Logs())
	t.Logf("confirmed identity file removed from disk: %s", evt.Id.Identifier)
}
