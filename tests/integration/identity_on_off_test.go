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
	"testing"
	"time"

	"github.com/openziti/ziti-tunnel-sdk-c/tests/integration/testutil"
	"github.com/stretchr/testify/require"
)

func TestIdentityOnOff(t *testing.T) {
	t.Run("togglesActiveOff", testIdentityOnOffTogglesActiveOff)
	t.Run("togglesActiveOn", testIdentityOnOffTogglesActiveOn)
}

func testIdentityOnOffTogglesActiveOff(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
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

	added := events.WaitFor(t, ctx, "identity", "added", name)
	require.NotEmpty(t, added.Id.Identifier, "identity:added Identifier empty")

	t.Logf("sending IdentityOnOff(false) for %q", name)
	offResp, err := client.IdentityOnOff(ctx, added.Id.Identifier, false)
	require.NoError(t, err, "IdentityOnOff(false) send\n%s", zet.Logs())
	require.True(t, offResp.Success, "IdentityOnOff(false) failed: error=%q code=%d", offResp.Error, offResp.Code)

	updated := events.WaitFor(t, ctx, "identity", "updated", name)
	require.False(t, updated.Id.Active, "identity:updated Active=%t after IdentityOnOff(false), want false", updated.Id.Active)
	t.Logf("identity:updated reports Active=%t after IdentityOnOff(false)", updated.Id.Active)
}

func testIdentityOnOffTogglesActiveOn(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
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

	added := events.WaitFor(t, ctx, "identity", "added", name)
	require.NotEmpty(t, added.Id.Identifier, "identity:added Identifier empty")

	t.Logf("sending IdentityOnOff(false) for %q", name)
	offResp, err := client.IdentityOnOff(ctx, added.Id.Identifier, false)
	require.NoError(t, err, "IdentityOnOff(false) send\n%s", zet.Logs())
	require.True(t, offResp.Success, "IdentityOnOff(false) failed: error=%q code=%d", offResp.Error, offResp.Code)

	offUpdated := events.WaitFor(t, ctx, "identity", "updated", name)
	require.False(t, offUpdated.Id.Active, "identity:updated Active=%t after IdentityOnOff(false), want false", offUpdated.Id.Active)

	t.Logf("sending IdentityOnOff(true) for %q", name)
	onResp, err := client.IdentityOnOff(ctx, added.Id.Identifier, true)
	require.NoError(t, err, "IdentityOnOff(true) send\n%s", zet.Logs())
	require.True(t, onResp.Success, "IdentityOnOff(true) failed: error=%q code=%d", onResp.Error, onResp.Code)

	onUpdated := events.WaitFor(t, ctx, "identity", "updated", name)
	require.True(t, onUpdated.Id.Active, "identity:updated Active=%t after IdentityOnOff(true), want true", onUpdated.Id.Active)
	t.Logf("identity:updated reports Active=%t after IdentityOnOff(true)", onUpdated.Id.Active)
}
