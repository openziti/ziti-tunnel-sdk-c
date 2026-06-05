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
	"testing"

	"github.com/openziti/ziti-tunnel-sdk-c/tests/integration/testutil"
)

func TestUrlEnrollment(t *testing.T) {
	state.overlay.RequireCATrusted(t)
	t.Run("withValidControllerUrlSucceeds", withValidControllerUrlSucceeds)
	t.Run("withMalformedUrlFails", withMalformedUrlFails)
	t.Run("withNonZitiEndpointFails", withNonZitiEndpointFails)
	t.Run("sameNameTwiceSecondFails", sameNameTwiceSecondFails)
	t.Run("afterJwtSameNameFails", afterJwtSameNameFails)
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
		identityData := testutil.AddIdentityData{
			IdentityFilename: idName,
			ControllerURL:    &controllerURL,
		}
		addResp := state.zetClient.AddIdentity(t, identityData)
		addResp.AssertFail(500, "identity exists with the same name")
	})
}

func afterJwtSameNameFails(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		idName := "test_url_enroll_after_jwt"
		testutil.FetchAndEnrollJwt(t, state.overlay, state.zetClient, idName)

		controllerURL := state.overlay.ControllerHostPort()
		urlIdentityData := testutil.AddIdentityData{
			IdentityFilename: idName,
			ControllerURL:    &controllerURL,
		}
		addResp := state.zetClient.AddIdentity(t, urlIdentityData)
		addResp.AssertFail(500, "identity exists with the same name")
	})
}

func withNonZitiEndpointFails(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		nonZitiURL := "https://example.com"
		identityData := testutil.AddIdentityData{
			IdentityFilename: "test_url_enroll_non_ziti",
			ControllerURL:    &nonZitiURL,
		}

		addResp := state.zetClient.AddIdentity(t, identityData)
		addResp.AssertFail(500, "")
	})
}

func withMalformedUrlFails(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		badURL := "not-a-url"
		identityData := testutil.AddIdentityData{
			IdentityFilename: "test_url_enroll_malformed_url",
			ControllerURL:    &badURL,
		}

		addResp := state.zetClient.AddIdentity(t, identityData)
		addResp.AssertFail(500, "")
	})
}
