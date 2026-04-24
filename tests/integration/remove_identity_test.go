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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := testutil.DialIPC(ctx)
	require.NoError(t, err, "dial ZET IPC pipe")
	t.Cleanup(func() { _ = client.Close() })

	name := identityNameFor(t)

	jwt, err := overlay.CreateIdentityJWT(ctx, name)
	require.NoError(t, err, "mint JWT")
	require.NotEmpty(t, jwt)
	t.Logf("JWT minted for identity %q (%d bytes)", name, len(jwt))

	addResp, err := client.AddIdentity(ctx, testutil.AddIdentityData{
		IdentityFilename: name,
		JwtContent:       jwt,
	})
	require.NoError(t, err, "AddIdentity send\n%s", zet.Logs())
	require.True(t, addResp.Success, "AddIdentity failed: error=%q code=%d", addResp.Error, addResp.Code)
	t.Logf("AddIdentity succeeded: filename=%q code=%d", name, addResp.Code)

	idFile := zet.IdentityFile(name)
	info, err := os.Stat(idFile)
	require.NoError(t, err, "identity file should exist after AddIdentity")
	require.Greater(t, info.Size(), int64(0))
	t.Logf("identity file present before Remove: %s (%d bytes)", idFile, info.Size())

	identifier := zet.IdentityIdentifier(name)
	removeResp, err := client.RemoveIdentity(ctx, identifier)
	require.NoError(t, err, "RemoveIdentity send\n%s", zet.Logs())
	require.True(t, removeResp.Success, "RemoveIdentity failed: error=%q code=%d", removeResp.Error, removeResp.Code)
	t.Logf("RemoveIdentity succeeded: identifier=%s code=%d", identifier, removeResp.Code)

	_, statErr := os.Stat(idFile)
	require.True(t, os.IsNotExist(statErr), "identity file should be removed after RemoveIdentity: %s\n%s", idFile, zet.Logs())
}
