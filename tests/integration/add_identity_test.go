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
	t.Run("withJwtSucceeds", withJwtSucceeds)
	t.Run("sameJwtTwiceSecondFails", sameJwtTwiceSecondFails)
	t.Run("withInvalidJwtFails", withInvalidJwtFails)
	t.Run("withEmptyJwtFails", withEmptyJwtFails)
	t.Run("withDeletedIdentityFails", withDeletedIdentityFails)
	t.Run("withSlashInFilenameFails", withSlashInFilenameFails)
	t.Run("withDotDotInFilenameFails", withDotDotInFilenameFails)
	t.Run("filenameExceedsCharLimitFails", filenameExceedsCharLimitFails)
}

func withJwtSucceeds(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		testutil.FetchAndEnrollJwt(t, state.overlay, state.zetClient, testutil.IdentityName(t))
	})
}

func sameJwtTwiceSecondFails(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		identityName := testutil.IdentityName(t)
		jwt := state.overlay.GetJwtFromController(t, identityName)
		testutil.EnrollJwt(t, state.zetClient, identityName, jwt)

		identityData := testutil.AddIdentityData{
			IdentityFilename: identityName,
			JwtContent:       &jwt,
		}
		state.zetClient.AddIdentity(t, identityData).AssertFail(t, 500, "identity exists with the same name")
	})
}

func withInvalidJwtFails(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		identityName := testutil.IdentityName(t)
		badJwt := "this.is.not-a-real-jwt"
		identityData := testutil.AddIdentityData{
			IdentityFilename: identityName,
			JwtContent:       &badJwt,
		}
		state.zetClient.AddIdentity(t, identityData).AssertFail(t, 500, "")
	})
}

func withEmptyJwtFails(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		identityName := testutil.IdentityName(t)
		emptyJwt := ""
		identityData := testutil.AddIdentityData{
			IdentityFilename: identityName,
			JwtContent:       &emptyJwt,
		}
		state.zetClient.AddIdentity(t, identityData).AssertFail(t, 500, "")
	})
}

func withDeletedIdentityFails(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		identityName := testutil.IdentityName(t)
		jwt := state.overlay.GetJwtFromController(t, identityName)

		t.Logf("deleting identity %q from overlay before ZET tries to enroll", identityName)
		require.NoError(t, state.overlay.DeleteIdentity(identityName), "delete identity via overlay")

		identityData := testutil.AddIdentityData{
			IdentityFilename: identityName,
			JwtContent:       &jwt,
		}
		state.zetClient.AddIdentity(t, identityData).AssertFail(t, 500, "")
	})
}

func withSlashInFilenameFails(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		jwt := state.overlay.GetJwtFromController(t, testutil.IdentityName(t))

		identityData := testutil.AddIdentityData{
			IdentityFilename: "foo/bar",
			JwtContent:       &jwt,
		}
		state.zetClient.AddIdentity(t, identityData).AssertFail(t, 500, "invalid file name")
	})
}

func withDotDotInFilenameFails(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		jwt := state.overlay.GetJwtFromController(t, testutil.IdentityName(t))

		identityData := testutil.AddIdentityData{
			IdentityFilename: "../escape",
			JwtContent:       &jwt,
		}
		state.zetClient.AddIdentity(t, identityData).AssertFail(t, 500, "not within the configuration directory")
	})
}

func filenameExceedsCharLimitFails(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		jwt := state.overlay.GetJwtFromController(t, testutil.IdentityName(t))

		longName := strings.Repeat("a", 5000)
		identityData := testutil.AddIdentityData{
			IdentityFilename: longName,
			JwtContent:       &jwt,
		}
		state.zetClient.AddIdentity(t, identityData).AssertFail(t, 500, "invalid file name")
	})
}
