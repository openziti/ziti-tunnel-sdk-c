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
	"github.com/stretchr/testify/require"
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
		testutil.EnrollUrlIdentityToNone(t, state.overlay, state.zetClient, testutil.IdentityName(t))
	})
}

func sameNameTwiceSecondFails(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		identityName := testutil.IdentityName(t)
		controllerURL := state.overlay.ControllerHostPort()
		identityData := testutil.AddIdentityData{
			IdentityFilename: identityName,
			ControllerURL:    &controllerURL,
		}

		first := testutil.AddIdentity(t, state.zetClient.CommandsClient, identityData)
		require.True(t, first.Success(), "first URL AddIdentity should succeed: error=%q\n%s", first.Error, state.zetClient.LogFile())
		state.zetClient.WaitForIdentityEvent(t, "needs_ext_login", identityName)

		second := testutil.AddIdentity(t, state.zetClient.CommandsClient, identityData)
		require.False(t, second.Success(), "second URL AddIdentity should fail, got Success=true")
		require.Equal(t, 500, second.Code, "expected Code=500, got %d", second.Code)
		require.Contains(t, second.Error, "identity exists", "expected duplicate-name error, got %q", second.Error)
	})
}

func afterJwtSameNameFails(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		identityName := testutil.IdentityName(t)
		testutil.EnrollImportedJwt(t, state.overlay, state.zetClient, identityName)

		controllerURL := state.overlay.ControllerHostPort()
		urlIdentityData := testutil.AddIdentityData{
			IdentityFilename: identityName,
			ControllerURL:    &controllerURL,
		}
		second := testutil.AddIdentity(t, state.zetClient.CommandsClient, urlIdentityData)
		require.False(t, second.Success(), "URL AddIdentity should fail when name already enrolled via JWT, got Success=true")
		require.Equal(t, 500, second.Code, "expected Code=500, got %d", second.Code)
		require.Contains(t, second.Error, "identity exists", "expected duplicate-name error, got %q", second.Error)
	})
}

func withNonZitiEndpointFails(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		identityName := testutil.IdentityName(t)
		nonZitiURL := "https://example.com"
		identityData := testutil.AddIdentityData{
			IdentityFilename: identityName,
			ControllerURL:    &nonZitiURL,
		}

		resp := testutil.AddIdentity(t, state.zetClient.CommandsClient, identityData)
		require.False(t, resp.Success(), "non-Ziti URL %q should be rejected, got Success=true\n%s", nonZitiURL, state.zetClient.LogFile())
		require.Equal(t, 500, resp.Code, "expected Code=500, got %d", resp.Code)
	})
}

func withMalformedUrlFails(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		identityName := testutil.IdentityName(t)
		badURL := "not-a-url"
		identityData := testutil.AddIdentityData{
			IdentityFilename: identityName,
			ControllerURL:    &badURL,
		}

		resp := testutil.AddIdentity(t, state.zetClient.CommandsClient, identityData)
		require.False(t, resp.Success(), "malformed URL %q should be rejected, got Success=true\n%s", badURL, state.zetClient.LogFile())
		require.Equal(t, 500, resp.Code, "expected Code=500, got %d", resp.Code)
	})
}
