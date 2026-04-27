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
	"strings"
	"testing"
	"time"

	"github.com/openziti/ziti-tunnel-sdk-c/tests/integration/testutil"
	"github.com/stretchr/testify/require"
)

func TestAddIdentity(t *testing.T) {
	t.Run("withJwtSucceeds", testAddIdentityWithJwtSucceeds)
	t.Run("sameJwtTwiceSecondFails", testAddIdentitySameJwtTwiceSecondFails)
	t.Run("withInvalidJwtFails", testAddIdentityWithInvalidJwtFails)
}

// identityNameFor returns a unique-per-test identity filename so tests sharing
// the package-level ZET instance don't collide on disk.
func identityNameFor(t *testing.T) string {
	// t.Name() is like "TestAddIdentity/withJwtSucceeds"
	return strings.ReplaceAll(t.Name(), "/", "-")
}

func testAddIdentityWithJwtSucceeds(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	identityName := identityNameFor(t)
	jwt, err := overlay.CreateIdentityJWT(ctx, identityName)
	require.NoError(t, err, "mint JWT via overlay")
	require.NotEmpty(t, jwt, "JWT content should not be empty")
	t.Logf("JWT minted for identity %q (%d bytes)", identityName, len(jwt))

	client, err := testutil.DialIPC(ctx)
	require.NoError(t, err, "dial ZET IPC pipe")
	t.Cleanup(func() { _ = client.Close() })

	identityData := testutil.AddIdentityData{
		IdentityFilename: identityName,
		JwtContent:       jwt,
	}

	resp, err := client.AddIdentity(ctx, identityData)
	require.NoError(t, err, "send AddIdentity command\n%s", zet.Logs())
	require.True(t, resp.Success, "AddIdentity failed: error=%q code=%d\n%s", resp.Error, resp.Code, zet.Logs())
	t.Logf("AddIdentity succeeded: filename=%q code=%d", identityName, resp.Code)

	info, err := os.Stat(zet.IdentityFile(identityName))
	require.NoError(t, err, "identity file should be written to -I dir")
	require.Greater(t, info.Size(), int64(0), "identity file should be non-empty")
	t.Logf("identity file written: %s (%d bytes)", zet.IdentityFile(identityName), info.Size())
}

func testAddIdentitySameJwtTwiceSecondFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	identityName := identityNameFor(t)
	jwt, err := overlay.CreateIdentityJWT(ctx, identityName)
	require.NoError(t, err, "mint JWT via overlay")
	require.NotEmpty(t, jwt)
	t.Logf("JWT minted for identity %q (%d bytes)", identityName, len(jwt))

	client, err := testutil.DialIPC(ctx)
	require.NoError(t, err, "dial ZET IPC pipe")
	t.Cleanup(func() { _ = client.Close() })

	identityData := testutil.AddIdentityData{
		IdentityFilename: identityName,
		JwtContent:       jwt,
	}

	first, err := client.AddIdentity(ctx, identityData)
	require.NoError(t, err, "first AddIdentity send\n%s", zet.Logs())
	require.True(t, first.Success, "first AddIdentity should succeed: error=%q\n%s", first.Error, zet.Logs())
	t.Logf("first AddIdentity succeeded")

	second, err := client.AddIdentity(ctx, identityData)
	require.NoError(t, err, "second AddIdentity send\n%s", zet.Logs())
	require.False(t, second.Success, "second AddIdentity should fail, got Success=true")
	require.Contains(t, second.Error, "identity exists",
		"expected duplicate-name error, got %q", second.Error)
	t.Logf("second AddIdentity correctly rejected: %s", second.Error)
}

func testAddIdentityWithInvalidJwtFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := testutil.DialIPC(ctx)
	require.NoError(t, err, "dial ZET IPC pipe")
	t.Cleanup(func() { _ = client.Close() })

	identityName := identityNameFor(t)
	identityData := testutil.AddIdentityData{
		IdentityFilename: identityName,
		JwtContent:       "this.is.not-a-real-jwt",
	}
	resp, err := client.AddIdentity(ctx, identityData)
	require.NoError(t, err, "IPC send should succeed even when enrollment fails\n%s", zet.Logs())
	require.False(t, resp.Success, "invalid JWT should be rejected, got Success=true")
	require.NotEqual(t, 0, resp.Code, "expected non-zero error code for invalid JWT")
	t.Logf("invalid JWT correctly rejected: code=%d error=%q", resp.Code, resp.Error)

	idFile := zet.IdentityFile(identityName)
	_, statErr := os.Stat(idFile)
	require.True(t, os.IsNotExist(statErr), "identity file should not exist after failed enroll: %s\n%s", idFile, zet.Logs())
}
