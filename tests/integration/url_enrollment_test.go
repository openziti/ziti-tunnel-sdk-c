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

type urlEnrollmentContext struct {
	overlay *testutil.Overlay
	zet     *testutil.ZET
}

func newUrlEnrollmentContext(t *testing.T) *urlEnrollmentContext {
	state.overlay.RequireCATrusted(t)
	return &urlEnrollmentContext{
		overlay: state.overlay,
		zet:     state.zetClient,
	}
}

func TestUrlEnrollment(t *testing.T) {
	c := newUrlEnrollmentContext(t)
	t.Run("withValidControllerUrlSucceeds", c.testUrlEnrollmentWithValidControllerUrlSucceeds)
	t.Run("withMalformedUrlFails", c.testUrlEnrollmentWithMalformedUrlFails)
	t.Run("withNonZitiEndpointFails", c.testUrlEnrollmentWithNonZitiEndpointFails)
	t.Run("sameNameTwiceSecondFails", c.testUrlEnrollmentSameNameTwiceSecondFails)
	t.Run("afterJwtSameNameFails", c.testUrlEnrollmentAfterJwtSameNameFails)
}

// testUrlEnrollmentWithValidControllerUrlSucceeds exercises the "URL + no enroll-to mode" path.
func (c *urlEnrollmentContext) testUrlEnrollmentWithValidControllerUrlSucceeds(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		testutil.EnrollUrlIdentityToNone(t, c.overlay, c.zet, testutil.IdentityName(t))
	})
}

func (c *urlEnrollmentContext) testUrlEnrollmentSameNameTwiceSecondFails(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		identityName := testutil.IdentityName(t)
		controllerURL := c.overlay.ControllerHostPort()
		identityData := testutil.AddIdentityData{
			IdentityFilename: identityName,
			ControllerURL:    &controllerURL,
		}

		first := testutil.AddIdentity(t, c.zet.Commands, identityData)
		require.True(t, first.Success(), "first URL AddIdentity should succeed: error=%q\n%s", first.Error, c.zet.LogFile())
		c.zet.Events.WaitForIdentityEvent(t, "needs_ext_login", identityName)

		second := testutil.AddIdentity(t, c.zet.Commands, identityData)
		require.False(t, second.Success(), "second URL AddIdentity should fail, got Success=true")
		require.Equal(t, 500, second.Code, "expected Code=500, got %d", second.Code)
		require.Contains(t, second.Error, "identity exists", "expected duplicate-name error, got %q", second.Error)
	})
}

func (c *urlEnrollmentContext) testUrlEnrollmentAfterJwtSameNameFails(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		identityName := testutil.IdentityName(t)
		testutil.EnrollImportedJwt(t, c.overlay, c.zet, identityName)

		controllerURL := c.overlay.ControllerHostPort()
		urlIdentityData := testutil.AddIdentityData{
			IdentityFilename: identityName,
			ControllerURL:    &controllerURL,
		}
		second := testutil.AddIdentity(t, c.zet.Commands, urlIdentityData)
		require.False(t, second.Success(), "URL AddIdentity should fail when name already enrolled via JWT, got Success=true")
		require.Equal(t, 500, second.Code, "expected Code=500, got %d", second.Code)
		require.Contains(t, second.Error, "identity exists", "expected duplicate-name error, got %q", second.Error)
	})
}

func (c *urlEnrollmentContext) testUrlEnrollmentWithNonZitiEndpointFails(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		identityName := testutil.IdentityName(t)
		nonZitiURL := "https://example.com"
		identityData := testutil.AddIdentityData{
			IdentityFilename: identityName,
			ControllerURL:    &nonZitiURL,
		}

		resp := testutil.AddIdentity(t, c.zet.Commands, identityData)
		require.False(t, resp.Success(), "non-Ziti URL %q should be rejected, got Success=true\n%s", nonZitiURL, c.zet.LogFile())
		require.Equal(t, 500, resp.Code, "expected Code=500, got %d", resp.Code)
	})
}

func (c *urlEnrollmentContext) testUrlEnrollmentWithMalformedUrlFails(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		identityName := testutil.IdentityName(t)
		badURL := "not-a-url"
		identityData := testutil.AddIdentityData{
			IdentityFilename: identityName,
			ControllerURL:    &badURL,
		}

		resp := testutil.AddIdentity(t, c.zet.Commands, identityData)
		require.False(t, resp.Success(), "malformed URL %q should be rejected, got Success=true\n%s", badURL, c.zet.LogFile())
		require.Equal(t, 500, resp.Code, "expected Code=500, got %d", resp.Code)
	})
}
