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
	"path/filepath"
	"testing"
	"time"

	"github.com/openziti/ziti-tunnel-sdk-c/tests/integration/testutil"
	"github.com/stretchr/testify/require"
)

func TestAddIdentity_JWT(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	identityName := "test-add-identity"
	jwt, err := overlay.CreateIdentityJWT(ctx, identityName)
	require.NoError(t, err, "mint JWT via overlay")
	require.NotEmpty(t, jwt, "JWT content should not be empty")
	t.Logf("JWT minted for identity %q (%d bytes)", identityName, len(jwt))

	identityDir := filepath.Join(tempRoot, t.Name())
	zet, err := testutil.StartZET(ctx, zetBin, identityDir)
	require.NoError(t, err, "start ziti-edge-tunnel")
	t.Cleanup(zet.Stop)
	t.Logf("ziti-edge-tunnel started, identity dir: %s", identityDir)

	client, err := testutil.DialIPC(ctx)
	require.NoError(t, err, "dial ZET IPC pipe")
	t.Cleanup(func() { _ = client.Close() })
	t.Logf("IPC pipe dialed: %s", testutil.CommandPipePath)

	resp, err := client.AddIdentity(ctx, testutil.AddIdentityData{
		IdentityFilename: identityName,
		JwtContent:       jwt,
	})
	require.NoError(t, err, "send AddIdentity command\n%s", zet.Logs())
	require.True(t, resp.Success, "AddIdentity failed: error=%q code=%d\n%s",
		resp.Error, resp.Code, zet.Logs())
	t.Logf("AddIdentity succeeded: filename=%q code=%d", identityName, resp.Code)

	info, err := os.Stat(zet.IdentityFile(identityName))
	require.NoError(t, err, "identity file should be written to -I dir")
	require.Greater(t, info.Size(), int64(0), "identity file should be non-empty")
	t.Logf("identity file written: %s (%d bytes)", zet.IdentityFile(identityName), info.Size())
}
