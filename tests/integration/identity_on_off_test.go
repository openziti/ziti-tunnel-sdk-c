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
	"encoding/json"
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

	client, err := testutil.DialIPC(ctx)
	require.NoError(t, err, "dial ZET IPC pipe")
	t.Cleanup(func() { _ = client.Close() })

	name := identityNameFor(t)
	jwt, err := overlay.CreateIdentityJWT(ctx, name)
	require.NoError(t, err, "mint JWT")
	require.NotEmpty(t, jwt)
	t.Logf("JWT minted for identity %q (%d bytes)", name, len(jwt))

	identityData := testutil.AddIdentityData{
		IdentityFilename: name,
		JwtContent:       &jwt,
	}
	addResp, err := client.AddIdentity(ctx, identityData)
	require.NoError(t, err, "AddIdentity send\n%s", zet.Logs())
	require.True(t, addResp.Success, "AddIdentity failed: error=%q code=%d", addResp.Error, addResp.Code)

	statusResp, err := client.Status(ctx)
	require.NoError(t, err, "Status send\n%s", zet.Logs())
	require.True(t, statusResp.Success, "Status failed: error=%q code=%d", statusResp.Error, statusResp.Code)

	var status struct {
		Identities []struct {
			Name       string `json:"Name"`
			Identifier string `json:"Identifier"`
			Active     bool   `json:"Active"`
		} `json:"Identities"`
	}
	require.NoError(t, json.Unmarshal(statusResp.Data, &status), "parse Status: %s", statusResp.Data)

	var identifier string
	for _, id := range status.Identities {
		if id.Name == name {
			identifier = id.Identifier
			break
		}
	}
	require.NotEmpty(t, identifier, "identity %q not found in Status.Identities", name)

	offResp, err := client.IdentityOnOff(ctx, identifier, false)
	require.NoError(t, err, "IdentityOnOff(false) send\n%s", zet.Logs())
	require.True(t, offResp.Success, "IdentityOnOff(false) failed: error=%q code=%d", offResp.Error, offResp.Code)
	t.Logf("IdentityOnOff(false) succeeded")

	statusResp, err = client.Status(ctx)
	require.NoError(t, err, "Status send after off\n%s", zet.Logs())
	require.NoError(t, json.Unmarshal(statusResp.Data, &status), "parse Status: %s", statusResp.Data)
	found := false
	for _, id := range status.Identities {
		if id.Name == name {
			require.False(t, id.Active, "Status.Identities[%q].Active should be false after IdentityOnOff(false)", name)
			found = true
			break
		}
	}
	require.True(t, found, "identity %q not found in Status after off", name)
}

func testIdentityOnOffTogglesActiveOn(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	client, err := testutil.DialIPC(ctx)
	require.NoError(t, err, "dial ZET IPC pipe")
	t.Cleanup(func() { _ = client.Close() })

	name := identityNameFor(t)
	jwt, err := overlay.CreateIdentityJWT(ctx, name)
	require.NoError(t, err, "mint JWT")
	require.NotEmpty(t, jwt)
	t.Logf("JWT minted for identity %q (%d bytes)", name, len(jwt))

	identityData := testutil.AddIdentityData{
		IdentityFilename: name,
		JwtContent:       &jwt,
	}
	addResp, err := client.AddIdentity(ctx, identityData)
	require.NoError(t, err, "AddIdentity send\n%s", zet.Logs())
	require.True(t, addResp.Success, "AddIdentity failed: error=%q code=%d", addResp.Error, addResp.Code)

	statusResp, err := client.Status(ctx)
	require.NoError(t, err, "Status send\n%s", zet.Logs())
	require.True(t, statusResp.Success, "Status failed: error=%q code=%d", statusResp.Error, statusResp.Code)

	var status struct {
		Identities []struct {
			Name       string `json:"Name"`
			Identifier string `json:"Identifier"`
			Active     bool   `json:"Active"`
		} `json:"Identities"`
	}
	require.NoError(t, json.Unmarshal(statusResp.Data, &status), "parse Status: %s", statusResp.Data)

	var identifier string
	for _, id := range status.Identities {
		if id.Name == name {
			identifier = id.Identifier
			break
		}
	}
	require.NotEmpty(t, identifier, "identity %q not found in Status.Identities", name)

	offResp, err := client.IdentityOnOff(ctx, identifier, false)
	require.NoError(t, err, "IdentityOnOff(false) send\n%s", zet.Logs())
	require.True(t, offResp.Success, "IdentityOnOff(false) failed: error=%q code=%d", offResp.Error, offResp.Code)

	onResp, err := client.IdentityOnOff(ctx, identifier, true)
	require.NoError(t, err, "IdentityOnOff(true) send\n%s", zet.Logs())
	require.True(t, onResp.Success, "IdentityOnOff(true) failed: error=%q code=%d", onResp.Error, onResp.Code)
	t.Logf("IdentityOnOff(true) succeeded")

	statusResp, err = client.Status(ctx)
	require.NoError(t, err, "Status send after on\n%s", zet.Logs())
	require.NoError(t, json.Unmarshal(statusResp.Data, &status), "parse Status: %s", statusResp.Data)
	found := false
	for _, id := range status.Identities {
		if id.Name == name {
			require.True(t, id.Active, "Status.Identities[%q].Active should be true after IdentityOnOff(true)", name)
			found = true
			break
		}
	}
	require.True(t, found, "identity %q not found in Status after on", name)
}
