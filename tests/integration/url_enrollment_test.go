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
	t.Run("withValidControllerUrlSucceeds", testUrlEnrollmentWithValidControllerUrlSucceeds)
	t.Run("withMalformedUrlFails", testUrlEnrollmentWithMalformedUrlFails)
	t.Run("withNonZitiEndpointFails", testUrlEnrollmentWithNonZitiEndpointFails)
	t.Run("sameNameTwiceSecondFails", testUrlEnrollmentSameNameTwiceSecondFails)
	t.Run("afterJwtSameNameFails", testUrlEnrollmentAfterJwtSameNameFails)
}

// testUrlEnrollmentWithValidControllerUrlSucceeds exercises the "URL + no enroll-to mode" path.
func testUrlEnrollmentWithValidControllerUrlSucceeds(t *testing.T) {
	testutil.RunTestWithTimeout(t, func(t *testing.T) {
		overlay := state.overlay
		events := state.zetClient.Events
		client := state.zetClient.Commands

		identityName := testutil.IdentityName(t)
		controllerURL := overlay.ControllerHostPort()
		identityData := testutil.AddIdentityData{
			IdentityFilename: identityName,
			ControllerURL:    &controllerURL,
		}

		resp := testutil.AddIdentity(t, client, identityData)
		require.True(t, resp.Success(), "URL AddIdentity failed: error=%q code=%d\n%s", resp.Error, resp.Code, state.zetClient.LogFile())

		event := events.WaitForIdentityEvent(t, "needs_ext_login", identityName)
		require.NotEmpty(t, event.Id.Identifier, "identity:needs_ext_login Identifier empty")
		require.True(t, event.Id.NeedsExtAuth, "identity:needs_ext_login NeedsExtAuth=%t", event.Id.NeedsExtAuth)

		testutil.AssertValidUrlEnrolledIdentityFile(t, event.Id.Identifier, testutil.EnrollModeNone)
		t.Logf("URL-enrolled identity:needs_ext_login Identifier=%s NeedsExtAuth=%t", event.Id.Identifier, event.Id.NeedsExtAuth)
	})
}

func testUrlEnrollmentSameNameTwiceSecondFails(t *testing.T) {
	testutil.RunTestWithTimeout(t, func(t *testing.T) {
		overlay := state.overlay
		events := state.zetClient.Events
		client := state.zetClient.Commands

		identityName := testutil.IdentityName(t)
		controllerURL := overlay.ControllerHostPort()
		identityData := testutil.AddIdentityData{
			IdentityFilename: identityName,
			ControllerURL:    &controllerURL,
		}

		first := testutil.AddIdentity(t, client, identityData)
		require.True(t, first.Success(), "first URL AddIdentity should succeed: error=%q\n%s", first.Error, state.zetClient.LogFile())
		events.WaitForIdentityEvent(t, "needs_ext_login", identityName)

		second := testutil.AddIdentity(t, client, identityData)
		require.False(t, second.Success(), "second URL AddIdentity should fail, got Success=true")
		require.Equal(t, 500, second.Code, "expected Code=500, got %d", second.Code)
		require.Contains(t, second.Error, "identity exists",
			"expected duplicate-name error, got %q", second.Error)
		t.Logf("second URL AddIdentity rejected: code=%d error=%q", second.Code, second.Error)
	})
}

func testUrlEnrollmentAfterJwtSameNameFails(t *testing.T) {
	testutil.RunTestWithTimeout(t, func(t *testing.T) {
		overlay := state.overlay
		client := state.zetClient.Commands

		identityName := testutil.IdentityName(t)
		testutil.EnrollJwtIdentity(t, overlay, state.zetClient, identityName)

		controllerURL := overlay.ControllerHostPort()
		urlIdentityData := testutil.AddIdentityData{
			IdentityFilename: identityName,
			ControllerURL:    &controllerURL,
		}
		second := testutil.AddIdentity(t, client, urlIdentityData)
		require.False(t, second.Success(), "URL AddIdentity should fail when name already enrolled via JWT, got Success=true")
		require.Equal(t, 500, second.Code, "expected Code=500, got %d", second.Code)
		require.Contains(t, second.Error, "identity exists", "expected duplicate-name error, got %q", second.Error)
		t.Logf("URL AddIdentity rejected after JWT enroll: code=%d error=%q", second.Code, second.Error)
	})
}

func testUrlEnrollmentWithNonZitiEndpointFails(t *testing.T) {
	testutil.RunTestWithTimeout(t, func(t *testing.T) {
		client := testutil.OpenCommandPipe(t, state.zetClient)

		identityName := testutil.IdentityName(t)
		nonZitiURL := "https://example.com"
		identityData := testutil.AddIdentityData{
			IdentityFilename: identityName,
			ControllerURL:    &nonZitiURL,
		}

		resp := testutil.AddIdentity(t, client, identityData)
		require.False(t, resp.Success(), "non-Ziti URL %q should be rejected, got Success=true\n%s", nonZitiURL, state.zetClient.LogFile())
		require.Equal(t, 500, resp.Code, "expected Code=500, got %d", resp.Code)
		t.Logf("non-Ziti URL rejected: code=%d error=%q", resp.Code, resp.Error)
	})
}

func testUrlEnrollmentWithMalformedUrlFails(t *testing.T) {
	testutil.RunTestWithTimeout(t, func(t *testing.T) {
		client := testutil.OpenCommandPipe(t, state.zetClient)

		identityName := testutil.IdentityName(t)
		badURL := "not-a-url"
		identityData := testutil.AddIdentityData{
			IdentityFilename: identityName,
			ControllerURL:    &badURL,
		}

		resp := testutil.AddIdentity(t, client, identityData)
		require.False(t, resp.Success(), "malformed URL %q should be rejected, got Success=true\n%s", badURL, state.zetClient.LogFile())
		require.Equal(t, 500, resp.Code, "expected Code=500, got %d", resp.Code)
		t.Logf("malformed URL rejected: code=%d error=%q", resp.Code, resp.Error)
	})
}
