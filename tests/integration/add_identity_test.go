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

func TestAddIdentityByJwt(t *testing.T) {
	// Happy path is tested throughout this suite
	t.Run("sameJwtTwiceSecondFails", sameJwtTwiceSecondFails)
	t.Run("withInvalidJwtFails", withInvalidJwtFails)
	t.Run("withEmptyJwtFails", withEmptyJwtFails)
	t.Run("withDeletedIdentityFails", withDeletedIdentityFails)
	t.Run("withSlashInFilenameFails", withSlashInFilenameFails)
	t.Run("withDotDotInFilenameFails", withDotDotInFilenameFails)
	t.Run("filenameExceedsCharLimitFails", filenameExceedsCharLimitFails)
}

func TestAddIdentityByUrl(t *testing.T) {
	state.overlay.RequireCATrusted(t)
	t.Run("withValidControllerUrlSucceeds", withValidControllerUrlSucceeds)
	t.Run("withMalformedUrlFails", withMalformedUrlFails)
	t.Run("withNonZitiEndpointFails", withNonZitiEndpointFails)
	t.Run("sameNameTwiceSecondFails", sameNameTwiceSecondFails)
	t.Run("afterJwtSameNameFails", afterJwtSameNameFails)
}

func sameJwtTwiceSecondFails(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		idName := "test_add_id_dup_name"
		jwt := state.overlay.GetJwtFromController(t, idName)
		testutil.EnrollJwt(t, state.zetClient, idName, jwt)

		identityData := testutil.NewJwtIdentityData(idName, jwt)
		addResp := state.zetClient.AddIdentity(t, identityData)
		addResp.AssertFail(500, "identity exists with the same name")
	})
}

func withInvalidJwtFails(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		badJwt := "this.is.not-a-real-jwt"
		identityData := testutil.NewJwtIdentityData("test_add_id_invalid_jwt", badJwt)
		addResp := state.zetClient.AddIdentity(t, identityData)
		addResp.AssertFail(500, "")
	})
}

func withEmptyJwtFails(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		emptyJwt := ""
		identityData := testutil.NewJwtIdentityData("test_add_id_empty_jwt", emptyJwt)
		addResp := state.zetClient.AddIdentity(t, identityData)
		addResp.AssertFail(500, "")
	})
}

func withDeletedIdentityFails(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		idName := "test_add_id_deleted"
		jwt := state.overlay.GetJwtFromController(t, idName)

		t.Logf("deleting identity %q from overlay before ZET tries to enroll", idName)
		require.NoError(t, state.overlay.DeleteIdentity(idName), "delete identity via overlay")

		identityData := testutil.NewJwtIdentityData(idName, jwt)
		addResp := state.zetClient.AddIdentity(t, identityData)
		addResp.AssertFail(500, "")
	})
}

func withSlashInFilenameFails(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		jwt := state.overlay.GetJwtFromController(t, "test_add_id_slash")

		identityData := testutil.NewJwtIdentityData("foo/bar", jwt)
		addResp := state.zetClient.AddIdentity(t, identityData)
		addResp.AssertFail(500, "invalid file name")
	})
}

func withDotDotInFilenameFails(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		jwt := state.overlay.GetJwtFromController(t, "test_add_id_dotdot")

		identityData := testutil.NewJwtIdentityData("../escape", jwt)
		addResp := state.zetClient.AddIdentity(t, identityData)
		addResp.AssertFail(500, "not within the configuration directory")
	})
}

func filenameExceedsCharLimitFails(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		jwt := state.overlay.GetJwtFromController(t, "test_add_id_long_name")

		longName := strings.Repeat("a", 5000)
		identityData := testutil.NewJwtIdentityData(longName, jwt)
		addResp := state.zetClient.AddIdentity(t, identityData)
		addResp.AssertFail(500, "invalid file name")
	})
}

// withValidControllerUrlSucceeds exercises the "URL + no enroll-to mode" path.
func withValidControllerUrlSucceeds(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		testutil.EnrollUrlIdentityToNone(t, state.overlay, state.zetClient, "test_url_enroll_happy")
	})
}

func sameNameTwiceSecondFails(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		idName := "test_url_enroll_dup_name"
		testutil.EnrollUrlIdentityToNone(t, state.overlay, state.zetClient, idName)

		controllerURL := state.overlay.ControllerHostPort()
		identityData := testutil.NewUrlIdentityData(idName, controllerURL)
		addResp := state.zetClient.AddIdentity(t, identityData)
		addResp.AssertFail(500, "identity exists with the same name")
	})
}

func afterJwtSameNameFails(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		idName := "test_url_enroll_after_jwt"
		testutil.FetchAndEnrollJwt(t, state.overlay, state.zetClient, idName)

		controllerURL := state.overlay.ControllerHostPort()
		urlIdentityData := testutil.NewUrlIdentityData(idName, controllerURL)
		addResp := state.zetClient.AddIdentity(t, urlIdentityData)
		addResp.AssertFail(500, "identity exists with the same name")
	})
}

func withNonZitiEndpointFails(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		nonZitiURL := "https://example.com"
		identityData := testutil.NewUrlIdentityData("test_url_enroll_non_ziti", nonZitiURL)

		addResp := state.zetClient.AddIdentity(t, identityData)
		addResp.AssertFail(500, "")
	})
}

func withMalformedUrlFails(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		badURL := "not-a-url"
		identityData := testutil.NewUrlIdentityData("test_url_enroll_malformed_url", badURL)

		addResp := state.zetClient.AddIdentity(t, identityData)
		addResp.AssertFail(500, "")
	})
}
