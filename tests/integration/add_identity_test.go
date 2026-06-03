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

type addIdentityContext struct {
	overlay *testutil.Overlay
	zet     *testutil.ZET
}

func newAddIdentityContext() *addIdentityContext {
	return &addIdentityContext{
		overlay: state.overlay,
		zet:     state.zetClient,
	}
}

func TestAddIdentity(t *testing.T) {
	c := newAddIdentityContext()
	t.Run("withJwtSucceeds", c.testAddIdentityWithJwtSucceeds)
	t.Run("sameJwtTwiceSecondFails", c.testAddIdentitySameJwtTwiceSecondFails)
	t.Run("withInvalidJwtFails", c.testAddIdentityWithInvalidJwtFails)
	t.Run("withEmptyJwtFails", c.testAddIdentityWithEmptyJwtFails)
	t.Run("withDeletedIdentityFails", c.testAddIdentityWithDeletedIdentityFails)
	t.Run("withSlashInFilenameFails", c.testAddIdentityWithSlashInFilenameFails)
	t.Run("withDotDotInFilenameFails", c.testAddIdentityWithDotDotInFilenameFails)
	t.Run("filenameExceedsCharLimitFails", c.testAddIdentityFilenameExceedsCharLimitFails)
}

func (c *addIdentityContext) testAddIdentityWithJwtSucceeds(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		event := testutil.EnrollImportedJwt(t, c.overlay, c.zet, testutil.IdentityName(t))
		require.True(t, event.Id.Active, "identity:added Active=%t", event.Id.Active)
	})
}

func (c *addIdentityContext) testAddIdentitySameJwtTwiceSecondFails(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		identityName := testutil.IdentityName(t)
		jwt := c.overlay.GetJwtFromController(t, identityName)

		identityData := testutil.AddIdentityData{
			IdentityFilename: identityName,
			JwtContent:       &jwt,
		}

		first := testutil.AddIdentity(t, c.zet.Commands, identityData)
		require.True(t, first.Success(), "first AddIdentity should succeed: error=%q\n%s", first.Error, c.zet.LogPath())
		added := c.zet.Events.WaitForIdentityEvent(t, "added", identityName)
		testutil.AssertValidJwtEnrolledIdentityFile(t, added.Id.Identifier)

		second := testutil.AddIdentity(t, c.zet.Commands, identityData)
		require.False(t, second.Success(), "second AddIdentity should fail, got Success=true")
		require.Equal(t, 500, second.Code, "expected Code=500, got %d", second.Code)
		require.Contains(t, second.Error, "identity exists", "expected duplicate-name error, got %q", second.Error)
	})
}

func (c *addIdentityContext) testAddIdentityWithInvalidJwtFails(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		identityName := testutil.IdentityName(t)
		badJwt := "this.is.not-a-real-jwt"
		identityData := testutil.AddIdentityData{
			IdentityFilename: identityName,
			JwtContent:       &badJwt,
		}
		resp := testutil.AddIdentity(t, c.zet.Commands, identityData)
		require.False(t, resp.Success(), "invalid JWT should be rejected, got Success=true")
		require.Equal(t, 500, resp.Code, "expected Code=500, got %d", resp.Code)
	})
}

func (c *addIdentityContext) testAddIdentityWithEmptyJwtFails(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		identityName := testutil.IdentityName(t)
		emptyJwt := ""
		identityData := testutil.AddIdentityData{
			IdentityFilename: identityName,
			JwtContent:       &emptyJwt,
		}
		resp := testutil.AddIdentity(t, c.zet.Commands, identityData)
		require.False(t, resp.Success(), "empty JWT should be rejected, got Success=true")
		require.Equal(t, 500, resp.Code, "expected Code=500, got %d", resp.Code)
	})
}

func (c *addIdentityContext) testAddIdentityWithDeletedIdentityFails(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		identityName := testutil.IdentityName(t)
		jwt := c.overlay.GetJwtFromController(t, identityName)

		t.Logf("deleting identity %q from overlay before ZET tries to enroll", identityName)
		require.NoError(t, c.overlay.DeleteIdentity(identityName), "delete identity via overlay")

		identityData := testutil.AddIdentityData{
			IdentityFilename: identityName,
			JwtContent:       &jwt,
		}
		resp := testutil.AddIdentity(t, c.zet.Commands, identityData)
		require.False(t, resp.Success(), "JWT for deleted identity should be rejected, got Success=true")
		require.Equal(t, 500, resp.Code, "expected Code=500, got %d", resp.Code)
	})
}

func (c *addIdentityContext) testAddIdentityWithSlashInFilenameFails(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		jwt := c.overlay.GetJwtFromController(t, testutil.IdentityName(t))

		identityData := testutil.AddIdentityData{
			IdentityFilename: "foo/bar",
			JwtContent:       &jwt,
		}
		resp := testutil.AddIdentity(t, c.zet.Commands, identityData)
		require.False(t, resp.Success(), "filename with slash should be rejected, got Success=true")
		require.Equal(t, 500, resp.Code, "expected Code=500, got %d", resp.Code)
		require.Contains(t, resp.Error, "invalid file name", "expected invalid-file-name error, got %q", resp.Error)
	})
}

func (c *addIdentityContext) testAddIdentityWithDotDotInFilenameFails(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		jwt := c.overlay.GetJwtFromController(t, testutil.IdentityName(t))

		identityData := testutil.AddIdentityData{
			IdentityFilename: "../escape",
			JwtContent:       &jwt,
		}
		resp := testutil.AddIdentity(t, c.zet.Commands, identityData)
		require.False(t, resp.Success(), "filename with .. should be rejected, got Success=true")
		require.Equal(t, 500, resp.Code, "expected Code=500, got %d", resp.Code)
		require.Contains(t, resp.Error, "not within the configuration directory", "expected path-escape error, got %q", resp.Error)
	})
}

func (c *addIdentityContext) testAddIdentityFilenameExceedsCharLimitFails(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		jwt := c.overlay.GetJwtFromController(t, testutil.IdentityName(t))

		longName := strings.Repeat("a", 300)
		identityData := testutil.AddIdentityData{
			IdentityFilename: longName,
			JwtContent:       &jwt,
		}
		resp := testutil.AddIdentity(t, c.zet.Commands, identityData)
		require.False(t, resp.Success(), "long filename should be rejected, got Success=true")
		require.Equal(t, 500, resp.Code, "expected Code=500, got %d", resp.Code)
		require.True(t, strings.Contains(resp.Error, "invalid file name") || strings.Contains(resp.Error, "not within the configuration directory"), "expected invalid-file-name or path-containment error, got %q", resp.Error)
	})
}
