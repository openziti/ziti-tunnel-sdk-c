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
	"testing"
	"time"

	"github.com/openziti/ziti-tunnel-sdk-c/tests/integration/testutil"
	"github.com/stretchr/testify/require"
)

func TestUrlEnrollment(t *testing.T) {
	overlay.RequireCATrusted(t)
	t.Run("withValidControllerUrlSucceeds", testUrlEnrollmentWithValidControllerUrlSucceeds)
	t.Run("withMalformedUrlFails", testUrlEnrollmentWithMalformedUrlFails)
	t.Run("withNonZitiEndpointFails", testUrlEnrollmentWithNonZitiEndpointFails)
	t.Run("sameNameTwiceSecondFails", testUrlEnrollmentSameNameTwiceSecondFails)
	t.Run("afterJwtSameNameFails", testUrlEnrollmentAfterJwtSameNameFails)
}

// testUrlEnrollmentWithValidControllerUrlSucceeds exercises the "URL + no enroll-to mode" path.
func testUrlEnrollmentWithValidControllerUrlSucceeds(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	events := testutil.SubscribeEvents(t, ctx, zet)
	client := testutil.OpenCommandPipe(t, ctx, zet)

	identityName := testutil.IdentityName(t)
	controllerURL := overlay.ControllerHostPort()
	identityData := testutil.AddIdentityData{
		IdentityFilename: identityName,
		ControllerURL:    &controllerURL,
	}

	resp := testutil.Enroll(t, ctx, client, identityData)
	require.True(t, resp.Success, "URL AddIdentity failed: error=%q code=%d\n%s", resp.Error, resp.Code, zet.Logs())

	evt := events.WaitFor(t, ctx, "identity", "added", identityName)
	require.NotEmpty(t, evt.Id.Identifier, "identity:added Identifier empty")

	info, err := os.Stat(evt.Id.Identifier)
	require.NoError(t, err, "failed to stat identity file at %s", evt.Id.Identifier)
	require.Greater(t, info.Size(), int64(0), "identity file should be non-empty")
	t.Logf("URL-enrolled identity:added Identifier=%s; file size=%d", evt.Id.Identifier, info.Size())
}

func testUrlEnrollmentSameNameTwiceSecondFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	events := testutil.SubscribeEvents(t, ctx, zet)
	client := testutil.OpenCommandPipe(t, ctx, zet)

	identityName := testutil.IdentityName(t)
	controllerURL := overlay.ControllerHostPort()
	identityData := testutil.AddIdentityData{
		IdentityFilename: identityName,
		ControllerURL:    &controllerURL,
	}

	first := testutil.Enroll(t, ctx, client, identityData)
	require.True(t, first.Success, "first URL AddIdentity should succeed: error=%q\n%s", first.Error, zet.Logs())
	events.WaitFor(t, ctx, "identity", "added", identityName)

	second := testutil.Enroll(t, ctx, client, identityData)
	require.False(t, second.Success, "second URL AddIdentity should fail, got Success=true")
	require.Equal(t, 500, second.Code, "expected Code=500, got %d", second.Code)
	require.Contains(t, second.Error, "identity exists",
		"expected duplicate-name error, got %q", second.Error)
	t.Logf("second URL AddIdentity correctly rejected: code=%d error=%q", second.Code, second.Error)
}

func testUrlEnrollmentAfterJwtSameNameFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	identityName := testutil.IdentityName(t)
	t.Logf("creating JWT for %q", identityName)
	jwt, err := overlay.CreateIdentityJWT(ctx, identityName)
	require.NoError(t, err, "failed to create JWT via overlay")
	require.NotEmpty(t, jwt)

	events := testutil.SubscribeEvents(t, ctx, zet)
	client := testutil.OpenCommandPipe(t, ctx, zet)

	jwtIdentityData := testutil.AddIdentityData{
		IdentityFilename: identityName,
		JwtContent:       &jwt,
	}
	first := testutil.Enroll(t, ctx, client, jwtIdentityData)
	require.True(t, first.Success, "first JWT AddIdentity should succeed: error=%q\n%s", first.Error, zet.Logs())
	events.WaitFor(t, ctx, "identity", "added", identityName)

	controllerURL := overlay.ControllerHostPort()
	urlIdentityData := testutil.AddIdentityData{
		IdentityFilename: identityName,
		ControllerURL:    &controllerURL,
	}
	second := testutil.Enroll(t, ctx, client, urlIdentityData)
	require.False(t, second.Success, "URL AddIdentity should fail when name already enrolled via JWT, got Success=true")
	require.Equal(t, 500, second.Code, "expected Code=500, got %d", second.Code)
	require.Contains(t, second.Error, "identity exists", "expected duplicate-name error, got %q", second.Error)
	t.Logf("URL AddIdentity correctly rejected after JWT enroll: code=%d error=%q", second.Code, second.Error)
}

func testUrlEnrollmentWithNonZitiEndpointFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := testutil.OpenCommandPipe(t, ctx, zet)

	identityName := testutil.IdentityName(t)
	nonZitiURL := "https://example.com"
	identityData := testutil.AddIdentityData{
		IdentityFilename: identityName,
		ControllerURL:    &nonZitiURL,
	}

	resp := testutil.Enroll(t, ctx, client, identityData)
	require.False(t, resp.Success, "non-Ziti URL %q should be rejected, got Success=true\n%s", nonZitiURL, zet.Logs())
	require.Equal(t, 500, resp.Code, "expected Code=500, got %d", resp.Code)
	t.Logf("non-Ziti URL correctly rejected: code=%d error=%q", resp.Code, resp.Error)
}

func testUrlEnrollmentWithMalformedUrlFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := testutil.OpenCommandPipe(t, ctx, zet)

	identityName := testutil.IdentityName(t)
	badURL := "not-a-url"
	identityData := testutil.AddIdentityData{
		IdentityFilename: identityName,
		ControllerURL:    &badURL,
	}

	resp := testutil.Enroll(t, ctx, client, identityData)
	require.False(t, resp.Success, "malformed URL %q should be rejected, got Success=true\n%s", badURL, zet.Logs())
	require.Equal(t, 500, resp.Code, "expected Code=500, got %d", resp.Code)
	t.Logf("malformed URL correctly rejected: code=%d error=%q", resp.Code, resp.Error)
}
