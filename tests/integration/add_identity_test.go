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
	"os"
	"path/filepath"
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
	t.Run("withEmptyJwtFails", testAddIdentityWithEmptyJwtFails)
	t.Run("withDeletedIdentityFails", testAddIdentityWithDeletedIdentityFails)
	t.Run("withSlashInFilenameFails", testAddIdentityWithSlashInFilenameFails)
	t.Run("withDotDotInFilenameFails", testAddIdentityWithDotDotInFilenameFails)
	t.Run("filenameExceedsCharLimitFails", testAddIdentityFilenameExceedsCharLimitFails)
	t.Run("emitsIdentityAddedEvent", testAddIdentityEmitsIdentityAddedEvent)
}

func testAddIdentityWithJwtSucceeds(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	identityName := testutil.IdentityName(t)
	t.Logf("minting JWT for %q", identityName)
	jwt, err := overlay.CreateIdentityJWT(ctx, identityName)
	require.NoError(t, err, "mint JWT via overlay")
	require.NotEmpty(t, jwt, "JWT content should not be empty")

	client, err := zet.DialIPC(ctx)
	require.NoError(t, err, "dial ZET IPC pipe")
	t.Cleanup(func() { _ = client.Close() })

	identityData := testutil.AddIdentityData{
		IdentityFilename: identityName,
		JwtContent:       &jwt,
	}

	resp := testutil.Enroll(t, ctx, client, identityData)
	require.True(t, resp.Success, "AddIdentity failed: error=%q code=%d\n%s", resp.Error, resp.Code, zet.Logs())

	t.Logf("fetching tunnel status")
	status, err := client.GetTunnelStatus(ctx)
	require.NoError(t, err, "Status after AddIdentity\n%s", zet.Logs())
	entry := status.FindIdentity(identityName)
	require.NotNil(t, entry, "identity %q not found in Status after AddIdentity", identityName)
	info, err := os.Stat(entry.Identifier)
	require.NoError(t, err, "identity file should be written to -I dir")
	require.Greater(t, info.Size(), int64(0), "identity file should be non-empty")
	t.Logf("found %q in status; identity file written: %s (%d bytes)", identityName, entry.Identifier, info.Size())
}

func testAddIdentitySameJwtTwiceSecondFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	identityName := testutil.IdentityName(t)
	t.Logf("minting JWT for %q", identityName)
	jwt, err := overlay.CreateIdentityJWT(ctx, identityName)
	require.NoError(t, err, "mint JWT via overlay")
	require.NotEmpty(t, jwt)

	client, err := zet.DialIPC(ctx)
	require.NoError(t, err, "dial ZET IPC pipe")
	t.Cleanup(func() { _ = client.Close() })

	identityData := testutil.AddIdentityData{
		IdentityFilename: identityName,
		JwtContent:       &jwt,
	}

	first := testutil.Enroll(t, ctx, client, identityData)
	require.True(t, first.Success, "first AddIdentity should succeed: error=%q\n%s", first.Error, zet.Logs())

	second := testutil.Enroll(t, ctx, client, identityData)
	require.False(t, second.Success, "second AddIdentity should fail, got Success=true")
	require.Contains(t, second.Error, "identity exists",
		"expected duplicate-name error, got %q", second.Error)
	t.Logf("second AddIdentity correctly rejected: %s", second.Error)
}

func testAddIdentityWithInvalidJwtFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := zet.DialIPC(ctx)
	require.NoError(t, err, "dial ZET IPC pipe")
	t.Cleanup(func() { _ = client.Close() })

	identityName := testutil.IdentityName(t)
	badJwt := "this.is.not-a-real-jwt"
	identityData := testutil.AddIdentityData{
		IdentityFilename: identityName,
		JwtContent:       &badJwt,
	}
	resp := testutil.Enroll(t, ctx, client, identityData)
	require.False(t, resp.Success, "invalid JWT should be rejected, got Success=true")
	require.NotEqual(t, 0, resp.Code, "expected non-zero error code for invalid JWT")
	t.Logf("invalid JWT correctly rejected: code=%d error=%q", resp.Code, resp.Error)

	t.Logf("fetching tunnel status")
	status, err := client.GetTunnelStatus(ctx)
	require.NoError(t, err, "Status after failed AddIdentity\n%s", zet.Logs())
	idFile := filepath.Join(status.ConfigDir, identityName+".json")
	_, statErr := os.Stat(idFile)
	require.True(t, os.IsNotExist(statErr), "identity file should not exist after failed enroll: %s\n%s", idFile, zet.Logs())
	t.Logf("confirmed no identity file at %s", idFile)
}

func testAddIdentityWithEmptyJwtFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := zet.DialIPC(ctx)
	require.NoError(t, err, "dial ZET IPC pipe")
	t.Cleanup(func() { _ = client.Close() })

	identityName := testutil.IdentityName(t)
	emptyJwt := ""
	identityData := testutil.AddIdentityData{
		IdentityFilename: identityName,
		JwtContent:       &emptyJwt,
	}
	resp := testutil.Enroll(t, ctx, client, identityData)
	require.False(t, resp.Success, "empty JWT should be rejected, got Success=true")
	t.Logf("empty JWT correctly rejected: code=%d error=%q", resp.Code, resp.Error)

	t.Logf("fetching tunnel status")
	status, err := client.GetTunnelStatus(ctx)
	require.NoError(t, err, "Status after failed AddIdentity\n%s", zet.Logs())
	idFile := filepath.Join(status.ConfigDir, identityName+".json")
	_, statErr := os.Stat(idFile)
	require.True(t, os.IsNotExist(statErr), "identity file should not exist after failed enroll: %s\n%s", idFile, zet.Logs())
	t.Logf("confirmed no identity file at %s", idFile)
}

func testAddIdentityWithDeletedIdentityFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	identityName := testutil.IdentityName(t)
	t.Logf("minting JWT for %q", identityName)
	jwt, err := overlay.CreateIdentityJWT(ctx, identityName)
	require.NoError(t, err, "mint JWT via overlay")
	require.NotEmpty(t, jwt)

	t.Logf("deleting identity %q from overlay before ZET tries to enroll", identityName)
	require.NoError(t, overlay.DeleteIdentity(ctx, identityName), "delete identity via overlay")

	client, err := zet.DialIPC(ctx)
	require.NoError(t, err, "dial ZET IPC pipe")
	t.Cleanup(func() { _ = client.Close() })

	identityData := testutil.AddIdentityData{
		IdentityFilename: identityName,
		JwtContent:       &jwt,
	}
	resp := testutil.Enroll(t, ctx, client, identityData)
	require.False(t, resp.Success, "JWT for deleted identity should be rejected, got Success=true")
	t.Logf("JWT identity deleted from controller correctly rejected: code=%d error=%q", resp.Code, resp.Error)

	t.Logf("fetching tunnel status")
	status, err := client.GetTunnelStatus(ctx)
	require.NoError(t, err, "Status after failed AddIdentity\n%s", zet.Logs())
	idFile := filepath.Join(status.ConfigDir, identityName+".json")
	_, statErr := os.Stat(idFile)
	require.True(t, os.IsNotExist(statErr), "identity file should not exist after failed enroll: %s\n%s", idFile, zet.Logs())
	t.Logf("confirmed no identity file at %s", idFile)
}

func testAddIdentityWithSlashInFilenameFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := zet.DialIPC(ctx)
	require.NoError(t, err, "dial ZET IPC pipe")
	t.Cleanup(func() { _ = client.Close() })

	t.Logf("minting JWT for %q", testutil.IdentityName(t))
	jwt, err := overlay.CreateIdentityJWT(ctx, testutil.IdentityName(t))
	require.NoError(t, err, "mint JWT via overlay")
	require.NotEmpty(t, jwt)

	identityData := testutil.AddIdentityData{
		IdentityFilename: "foo/bar",
		JwtContent:       &jwt,
	}
	resp := testutil.Enroll(t, ctx, client, identityData)
	require.False(t, resp.Success, "filename with slash should be rejected, got Success=true")
	t.Logf("slash filename correctly rejected: code=%d error=%q", resp.Code, resp.Error)
}

func testAddIdentityWithDotDotInFilenameFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := zet.DialIPC(ctx)
	require.NoError(t, err, "dial ZET IPC pipe")
	t.Cleanup(func() { _ = client.Close() })

	t.Logf("minting JWT for %q", testutil.IdentityName(t))
	jwt, err := overlay.CreateIdentityJWT(ctx, testutil.IdentityName(t))
	require.NoError(t, err, "mint JWT via overlay")
	require.NotEmpty(t, jwt)

	identityData := testutil.AddIdentityData{
		IdentityFilename: "../escape",
		JwtContent:       &jwt,
	}
	resp := testutil.Enroll(t, ctx, client, identityData)
	require.False(t, resp.Success, "filename with .. should be rejected, got Success=true")
	t.Logf("dot-dot filename correctly rejected: code=%d error=%q", resp.Code, resp.Error)
}

func testAddIdentityFilenameExceedsCharLimitFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := zet.DialIPC(ctx)
	require.NoError(t, err, "dial ZET IPC pipe")
	t.Cleanup(func() { _ = client.Close() })

	t.Logf("minting JWT for %q", testutil.IdentityName(t))
	jwt, err := overlay.CreateIdentityJWT(ctx, testutil.IdentityName(t))
	require.NoError(t, err, "mint JWT via overlay")
	require.NotEmpty(t, jwt)

	longName := strings.Repeat("a", 300)
	identityData := testutil.AddIdentityData{
		IdentityFilename: longName,
		JwtContent:       &jwt,
	}
	resp := testutil.Enroll(t, ctx, client, identityData)
	require.False(t, resp.Success, "long filename should be rejected, got Success=true")
	t.Logf("long filename correctly rejected: code=%d error=%q", resp.Code, resp.Error)
}

func testAddIdentityEmitsIdentityAddedEvent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	identityName := testutil.IdentityName(t)
	t.Logf("minting JWT for %q", identityName)
	jwt, err := overlay.CreateIdentityJWT(ctx, identityName)
	require.NoError(t, err, "mint JWT via overlay")
	require.NotEmpty(t, jwt)

	events, err := zet.DialEvents(ctx)
	require.NoError(t, err, "dial ZET event pipe")
	t.Cleanup(func() { _ = events.Close() })

	client, err := zet.DialIPC(ctx)
	require.NoError(t, err, "dial ZET command pipe")
	t.Cleanup(func() { _ = client.Close() })

	identityData := testutil.AddIdentityData{
		IdentityFilename: identityName,
		JwtContent:       &jwt,
	}
	resp := testutil.Enroll(t, ctx, client, identityData)
	require.True(t, resp.Success, "AddIdentity failed: error=%q code=%d", resp.Error, resp.Code)

	t.Logf("waiting for identity:added event for %q", identityName)
	raw := events.WaitFor(t, ctx, "identity", "added", identityName)
	t.Logf("identity event received: %s", raw)
	var keys map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &keys), "parse identity event: %s", raw)
	require.Contains(t, keys, "Op", "identity event missing Op")
	require.Contains(t, keys, "Action", "identity event missing Action")
	require.Contains(t, keys, "Fingerprint", "identity event missing Fingerprint")
	require.Contains(t, keys, "Id", "identity event missing Id")
	require.Len(t, keys, 4, "identity event has unexpected key set: %v", keys)
}
