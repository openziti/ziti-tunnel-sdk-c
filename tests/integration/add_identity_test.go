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
	"strings"
	"testing"

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
	testutil.RunTestWithTimeout(t, func(t *testing.T) {
		overlay := state.overlay
		events := state.zetClient.Events
		client := state.zetClient.Commands

		identityName := testutil.IdentityName(t)
		t.Logf("creating JWT for %q", identityName)
		jwt, err := overlay.CreateIdentityJWT(identityName)
		require.NoError(t, err, "failed to create JWT via overlay")
		require.NotEmpty(t, jwt, "JWT content should not be empty")

		identityData := testutil.AddIdentityData{
			IdentityFilename: identityName,
			JwtContent:       &jwt,
		}

		resp := testutil.AddIdentity(t, client, identityData)
		require.True(t, resp.Success(), "AddIdentity failed: error=%q code=%d\n%s", resp.Error, resp.Code, state.zetClient.LogPath())

		event := events.WaitForIdentityEvent(t, "added", identityName)
		require.True(t, event.Id.Active, "identity:added Active=%t, want true", event.Id.Active)
		require.NotEmpty(t, event.Id.Identifier, "identity:added Identifier empty")

		testutil.AssertValidJwtEnrolledIdentityFile(t, event.Id.Identifier)
		t.Logf("identity:added Identifier=%s Active=%t", event.Id.Identifier, event.Id.Active)
	})
}

func testAddIdentitySameJwtTwiceSecondFails(t *testing.T) {
	testutil.RunTestWithTimeout(t, func(t *testing.T) {
		overlay := state.overlay
		events := state.zetClient.Events
		client := state.zetClient.Commands
		identityName := testutil.IdentityName(t)
		t.Logf("creating JWT for %q", identityName)
		jwt, err := overlay.CreateIdentityJWT(identityName)
		require.NoError(t, err, "failed to create JWT via overlay")
		require.NotEmpty(t, jwt)

		identityData := testutil.AddIdentityData{
			IdentityFilename: identityName,
			JwtContent:       &jwt,
		}

		first := testutil.AddIdentity(t, client, identityData)
		require.True(t, first.Success(), "first AddIdentity should succeed: error=%q\n%s", first.Error, state.zetClient.LogPath())
		added := events.WaitForIdentityEvent(t, "added", identityName)
		testutil.AssertValidJwtEnrolledIdentityFile(t, added.Id.Identifier)

		second := testutil.AddIdentity(t, client, identityData)
		require.False(t, second.Success(), "second AddIdentity should fail, got Success=true")
		require.Equal(t, 500, second.Code, "expected Code=500, got %d", second.Code)
		require.Contains(t, second.Error, "identity exists", "expected duplicate-name error, got %q", second.Error)
		t.Logf("second AddIdentity rejected: code=%d error=%q", second.Code, second.Error)
	})
}

func testAddIdentityWithInvalidJwtFails(t *testing.T) {
	testutil.RunTestWithTimeout(t, func(t *testing.T) {
		client := state.zetClient.Commands

		identityName := testutil.IdentityName(t)
		badJwt := "this.is.not-a-real-jwt"
		identityData := testutil.AddIdentityData{
			IdentityFilename: identityName,
			JwtContent:       &badJwt,
		}
		resp := testutil.AddIdentity(t, client, identityData)
		require.False(t, resp.Success(), "invalid JWT should be rejected, got Success=true")
		require.Equal(t, 500, resp.Code, "expected Code=500, got %d", resp.Code)
		t.Logf("invalid JWT rejected: code=%d error=%q", resp.Code, resp.Error)
	})
}

func testAddIdentityWithEmptyJwtFails(t *testing.T) {
	testutil.RunTestWithTimeout(t, func(t *testing.T) {
		client := state.zetClient.Commands

		identityName := testutil.IdentityName(t)
		emptyJwt := ""
		identityData := testutil.AddIdentityData{
			IdentityFilename: identityName,
			JwtContent:       &emptyJwt,
		}
		resp := testutil.AddIdentity(t, client, identityData)
		require.False(t, resp.Success(), "empty JWT should be rejected, got Success=true")
		require.Equal(t, 500, resp.Code, "expected Code=500, got %d", resp.Code)
		t.Logf("empty JWT rejected: code=%d error=%q", resp.Code, resp.Error)
	})
}

func testAddIdentityWithDeletedIdentityFails(t *testing.T) {
	testutil.RunTestWithTimeout(t, func(t *testing.T) {
		overlay := state.overlay
		client := state.zetClient.Commands

		identityName := testutil.IdentityName(t)
		t.Logf("creating JWT for %q", identityName)
		jwt, err := overlay.CreateIdentityJWT(identityName)
		require.NoError(t, err, "failed to create JWT via overlay")
		require.NotEmpty(t, jwt)

		t.Logf("deleting identity %q from overlay before ZET tries to enroll", identityName)
		require.NoError(t, overlay.DeleteIdentity(identityName), "delete identity via overlay")

		identityData := testutil.AddIdentityData{
			IdentityFilename: identityName,
			JwtContent:       &jwt,
		}
		resp := testutil.AddIdentity(t, client, identityData)
		require.False(t, resp.Success(), "JWT for deleted identity should be rejected, got Success=true")
		require.Equal(t, 500, resp.Code, "expected Code=500, got %d", resp.Code)
		t.Logf("JWT identity deleted from controller rejected: code=%d error=%q", resp.Code, resp.Error)
	})
}

func testAddIdentityWithSlashInFilenameFails(t *testing.T) {
	testutil.RunTestWithTimeout(t, func(t *testing.T) {
		overlay := state.overlay
		client := state.zetClient.Commands

		name := testutil.IdentityName(t)
		t.Logf("creating JWT for %q", name)
		jwt, err := overlay.CreateIdentityJWT(name)
		require.NoError(t, err, "failed to create JWT via overlay")
		require.NotEmpty(t, jwt)

		identityData := testutil.AddIdentityData{
			IdentityFilename: "foo/bar",
			JwtContent:       &jwt,
		}
		resp := testutil.AddIdentity(t, client, identityData)
		require.False(t, resp.Success(), "filename with slash should be rejected, got Success=true")
		require.Equal(t, 500, resp.Code, "expected Code=500, got %d", resp.Code)
		require.Contains(t, resp.Error, "invalid file name", "expected invalid-file-name error, got %q", resp.Error)
		t.Logf("slash filename rejected: code=%d error=%q", resp.Code, resp.Error)
	})
}

func testAddIdentityWithDotDotInFilenameFails(t *testing.T) {
	testutil.RunTestWithTimeout(t, func(t *testing.T) {
		overlay := state.overlay
		client := state.zetClient.Commands

		name := testutil.IdentityName(t)
		t.Logf("creating JWT for %q", name)
		jwt, err := overlay.CreateIdentityJWT(name)
		require.NoError(t, err, "failed to create JWT via overlay")
		require.NotEmpty(t, jwt)

		identityData := testutil.AddIdentityData{
			IdentityFilename: "../escape",
			JwtContent:       &jwt,
		}
		resp := testutil.AddIdentity(t, client, identityData)
		require.False(t, resp.Success(), "filename with .. should be rejected, got Success=true")
		require.Equal(t, 500, resp.Code, "expected Code=500, got %d", resp.Code)
		require.Contains(t, resp.Error, "not within the configuration directory", "expected path-escape error, got %q", resp.Error)
		t.Logf("dot-dot filename rejected: code=%d error=%q", resp.Code, resp.Error)
	})
}

func testAddIdentityFilenameExceedsCharLimitFails(t *testing.T) {
	testutil.RunTestWithTimeout(t, func(t *testing.T) {
		overlay := state.overlay
		client := state.zetClient.Commands

		name := testutil.IdentityName(t)
		t.Logf("creating JWT for %q", name)
		jwt, err := overlay.CreateIdentityJWT(name)
		require.NoError(t, err, "failed to create JWT via overlay")
		require.NotEmpty(t, jwt)

		longName := strings.Repeat("a", 300)
		identityData := testutil.AddIdentityData{
			IdentityFilename: longName,
			JwtContent:       &jwt,
		}
		resp := testutil.AddIdentity(t, client, identityData)
		require.False(t, resp.Success(), "long filename should be rejected, got Success=true")
		require.Equal(t, 500, resp.Code, "expected Code=500, got %d", resp.Code)
		require.True(t, strings.Contains(resp.Error, "invalid file name") || strings.Contains(resp.Error, "not within the configuration directory"),
			"expected invalid-file-name or path-containment error, got %q", resp.Error)
		t.Logf("long filename rejected: code=%d error=%q", resp.Code, resp.Error)
	})
}
