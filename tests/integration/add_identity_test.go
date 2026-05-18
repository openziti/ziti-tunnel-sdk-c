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
	t.Run("withEmptyJwtFails", testAddIdentityWithEmptyJwtFails)
	t.Run("withDeletedIdentityFails", testAddIdentityWithDeletedIdentityFails)
	t.Run("withSlashInFilenameFails", testAddIdentityWithSlashInFilenameFails)
	t.Run("withDotDotInFilenameFails", testAddIdentityWithDotDotInFilenameFails)
	t.Run("filenameExceedsCharLimitFails", testAddIdentityFilenameExceedsCharLimitFails)
}

func testAddIdentityWithJwtSucceeds(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	identityName := testutil.IdentityName(t)
	t.Logf("creating JWT for %q", identityName)
	jwt, err := overlay.CreateIdentityJWT(ctx, identityName)
	require.NoError(t, err, "failed to create JWT via overlay")
	require.NotEmpty(t, jwt, "JWT content should not be empty")

	events := testutil.SubscribeEvents(t, ctx, zet)
	client := testutil.OpenCommandPipe(t, ctx, zet)

	identityData := testutil.AddIdentityData{
		IdentityFilename: identityName,
		JwtContent:       &jwt,
	}

	resp := testutil.Enroll(t, ctx, client, identityData)
	require.True(t, resp.Success, "AddIdentity failed: error=%q code=%d\n%s", resp.Error, resp.Code, zet.Logs())

	evt := events.WaitFor(t, ctx, "identity", "added", identityName)
	require.True(t, evt.Id.Active, "identity:added Active=%t, want true", evt.Id.Active)
	require.NotEmpty(t, evt.Id.Identifier, "identity:added Identifier empty")

	info, err := os.Stat(evt.Id.Identifier)
	require.NoError(t, err, "failed to stat identity file at %s", evt.Id.Identifier)
	require.Greater(t, info.Size(), int64(0), "identity file should be non-empty")

	content := testutil.ReadIdentityFile(t, evt.Id.Identifier)
	require.NotEmpty(t, content.ZtAPI, "identity file ztAPI empty")
	require.NotEmpty(t, content.ID.Cert, "identity file id.cert empty")
	require.NotEmpty(t, content.ID.Key, "identity file id.key empty")
	require.NotEmpty(t, content.ID.CA, "identity file id.ca empty")
	t.Logf("identity:added Identifier=%s Active=%t; file size=%d", evt.Id.Identifier, evt.Id.Active, info.Size())
}

func testAddIdentitySameJwtTwiceSecondFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	identityName := testutil.IdentityName(t)
	t.Logf("creating JWT for %q", identityName)
	jwt, err := overlay.CreateIdentityJWT(ctx, identityName)
	require.NoError(t, err, "failed to create JWT via overlay")
	require.NotEmpty(t, jwt)

	events := testutil.SubscribeEvents(t, ctx, zet)
	client := testutil.OpenCommandPipe(t, ctx, zet)

	identityData := testutil.AddIdentityData{
		IdentityFilename: identityName,
		JwtContent:       &jwt,
	}

	first := testutil.Enroll(t, ctx, client, identityData)
	require.True(t, first.Success, "first AddIdentity should succeed: error=%q\n%s", first.Error, zet.Logs())
	events.WaitFor(t, ctx, "identity", "added", identityName)

	second := testutil.Enroll(t, ctx, client, identityData)
	require.False(t, second.Success, "second AddIdentity should fail, got Success=true")
	require.Equal(t, 500, second.Code, "expected Code=500, got %d", second.Code)
	require.Contains(t, second.Error, "identity exists", "expected duplicate-name error, got %q", second.Error)
	t.Logf("second AddIdentity correctly rejected: code=%d error=%q", second.Code, second.Error)
}

func testAddIdentityWithInvalidJwtFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := testutil.OpenCommandPipe(t, ctx, zet)

	identityName := testutil.IdentityName(t)
	badJwt := "this.is.not-a-real-jwt"
	identityData := testutil.AddIdentityData{
		IdentityFilename: identityName,
		JwtContent:       &badJwt,
	}
	resp := testutil.Enroll(t, ctx, client, identityData)
	require.False(t, resp.Success, "invalid JWT should be rejected, got Success=true")
	require.Equal(t, 500, resp.Code, "expected Code=500, got %d", resp.Code)
	t.Logf("invalid JWT correctly rejected: code=%d error=%q", resp.Code, resp.Error)
}

func testAddIdentityWithEmptyJwtFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := testutil.OpenCommandPipe(t, ctx, zet)

	identityName := testutil.IdentityName(t)
	emptyJwt := ""
	identityData := testutil.AddIdentityData{
		IdentityFilename: identityName,
		JwtContent:       &emptyJwt,
	}
	resp := testutil.Enroll(t, ctx, client, identityData)
	require.False(t, resp.Success, "empty JWT should be rejected, got Success=true")
	require.Equal(t, 500, resp.Code, "expected Code=500, got %d", resp.Code)
	t.Logf("empty JWT correctly rejected: code=%d error=%q", resp.Code, resp.Error)
}

func testAddIdentityWithDeletedIdentityFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	identityName := testutil.IdentityName(t)
	t.Logf("creating JWT for %q", identityName)
	jwt, err := overlay.CreateIdentityJWT(ctx, identityName)
	require.NoError(t, err, "failed to create JWT via overlay")
	require.NotEmpty(t, jwt)

	t.Logf("deleting identity %q from overlay before ZET tries to enroll", identityName)
	require.NoError(t, overlay.DeleteIdentity(ctx, identityName), "delete identity via overlay")

	client := testutil.OpenCommandPipe(t, ctx, zet)

	identityData := testutil.AddIdentityData{
		IdentityFilename: identityName,
		JwtContent:       &jwt,
	}
	resp := testutil.Enroll(t, ctx, client, identityData)
	require.False(t, resp.Success, "JWT for deleted identity should be rejected, got Success=true")
	require.Equal(t, 500, resp.Code, "expected Code=500, got %d", resp.Code)
	t.Logf("JWT identity deleted from controller correctly rejected: code=%d error=%q", resp.Code, resp.Error)
}

func testAddIdentityWithSlashInFilenameFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := testutil.OpenCommandPipe(t, ctx, zet)

	name := testutil.IdentityName(t)
	t.Logf("creating JWT for %q", name)
	jwt, err := overlay.CreateIdentityJWT(ctx, name)
	require.NoError(t, err, "failed to create JWT via overlay")
	require.NotEmpty(t, jwt)

	identityData := testutil.AddIdentityData{
		IdentityFilename: "foo/bar",
		JwtContent:       &jwt,
	}
	resp := testutil.Enroll(t, ctx, client, identityData)
	require.False(t, resp.Success, "filename with slash should be rejected, got Success=true")
	require.Equal(t, 500, resp.Code, "expected Code=500, got %d", resp.Code)
	require.Contains(t, resp.Error, "invalid file name", "expected invalid-file-name error, got %q", resp.Error)
	t.Logf("slash filename correctly rejected: code=%d error=%q", resp.Code, resp.Error)
}

func testAddIdentityWithDotDotInFilenameFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := testutil.OpenCommandPipe(t, ctx, zet)

	name := testutil.IdentityName(t)
	t.Logf("creating JWT for %q", name)
	jwt, err := overlay.CreateIdentityJWT(ctx, name)
	require.NoError(t, err, "failed to create JWT via overlay")
	require.NotEmpty(t, jwt)

	identityData := testutil.AddIdentityData{
		IdentityFilename: "../escape",
		JwtContent:       &jwt,
	}
	resp := testutil.Enroll(t, ctx, client, identityData)
	require.False(t, resp.Success, "filename with .. should be rejected, got Success=true")
	require.Equal(t, 500, resp.Code, "expected Code=500, got %d", resp.Code)
	require.Contains(t, resp.Error, "not within the configuration directory", "expected path-escape error, got %q", resp.Error)
	t.Logf("dot-dot filename correctly rejected: code=%d error=%q", resp.Code, resp.Error)
}

func testAddIdentityFilenameExceedsCharLimitFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := testutil.OpenCommandPipe(t, ctx, zet)

	name := testutil.IdentityName(t)
	t.Logf("creating JWT for %q", name)
	jwt, err := overlay.CreateIdentityJWT(ctx, name)
	require.NoError(t, err, "failed to create JWT via overlay")
	require.NotEmpty(t, jwt)

	longName := strings.Repeat("a", 300)
	identityData := testutil.AddIdentityData{
		IdentityFilename: longName,
		JwtContent:       &jwt,
	}
	resp := testutil.Enroll(t, ctx, client, identityData)
	require.False(t, resp.Success, "long filename should be rejected, got Success=true")
	require.Equal(t, 500, resp.Code, "expected Code=500, got %d", resp.Code)
	require.Contains(t, resp.Error, "invalid file name", "expected invalid-file-name error, got %q", resp.Error)
	t.Logf("long filename correctly rejected: code=%d error=%q", resp.Code, resp.Error)
}
