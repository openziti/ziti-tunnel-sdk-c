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
	// Happy path is tested throughout this suite
	t.Run("sameJwtTwiceSecondFails", sameJwtTwiceSecondFails)
	t.Run("withInvalidJwtFails", withInvalidJwtFails)
	t.Run("withEmptyJwtFails", withEmptyJwtFails)
	t.Run("withDeletedIdentityFails", withDeletedIdentityFails)
	t.Run("withSlashInFilenameFails", withSlashInFilenameFails)
	t.Run("withDotDotInFilenameFails", withDotDotInFilenameFails)
	t.Run("filenameExceedsCharLimitFails", filenameExceedsCharLimitFails)
}

func sameJwtTwiceSecondFails(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		idName := "test_add_id_dup_name"
		jwt := state.overlay.GetJwtFromController(t, idName)
		testutil.EnrollJwt(t, state.zetClient, idName, jwt)

		identityData := testutil.AddIdentityData{
			IdentityFilename: idName,
			JwtContent:       &jwt,
		}
		addResp := state.zetClient.AddIdentity(t, identityData)
		addResp.AssertFail(t, 500, "identity exists with the same name")
	})
}

func withInvalidJwtFails(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		badJwt := "this.is.not-a-real-jwt"
		identityData := testutil.AddIdentityData{
			IdentityFilename: "test_add_id_invalid_jwt",
			JwtContent:       &badJwt,
		}
		addResp := state.zetClient.AddIdentity(t, identityData)
		addResp.AssertFail(t, 500, "")
	})
}

func withEmptyJwtFails(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		emptyJwt := ""
		identityData := testutil.AddIdentityData{
			IdentityFilename: "test_add_id_empty_jwt",
			JwtContent:       &emptyJwt,
		}
		addResp := state.zetClient.AddIdentity(t, identityData)
		addResp.AssertFail(t, 500, "")
	})
}

func withDeletedIdentityFails(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		idName := "test_add_id_deleted"
		jwt := state.overlay.GetJwtFromController(t, idName)

		t.Logf("deleting identity %q from overlay before ZET tries to enroll", idName)
		require.NoError(t, state.overlay.DeleteIdentity(idName), "delete identity via overlay")

		identityData := testutil.AddIdentityData{
			IdentityFilename: idName,
			JwtContent:       &jwt,
		}
		addResp := state.zetClient.AddIdentity(t, identityData)
		addResp.AssertFail(t, 500, "")
	})
}

func withSlashInFilenameFails(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		jwt := state.overlay.GetJwtFromController(t, "test_add_id_slash")

		identityData := testutil.AddIdentityData{
			IdentityFilename: "foo/bar",
			JwtContent:       &jwt,
		}
		addResp := state.zetClient.AddIdentity(t, identityData)
		addResp.AssertFail(t, 500, "invalid file name")
	})
}

func withDotDotInFilenameFails(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		jwt := state.overlay.GetJwtFromController(t, "test_add_id_dotdot")

		identityData := testutil.AddIdentityData{
			IdentityFilename: "../escape",
			JwtContent:       &jwt,
		}
		addResp := state.zetClient.AddIdentity(t, identityData)
		addResp.AssertFail(t, 500, "not within the configuration directory")
	})
}

func filenameExceedsCharLimitFails(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		jwt := state.overlay.GetJwtFromController(t, "test_add_id_long_name")

		longName := strings.Repeat("a", 5000)
		identityData := testutil.AddIdentityData{
			IdentityFilename: longName,
			JwtContent:       &jwt,
		}
		addResp := state.zetClient.AddIdentity(t, identityData)
		addResp.AssertFail(t, 500, "invalid file name")
	})
}
