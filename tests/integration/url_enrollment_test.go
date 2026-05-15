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

	client, err := zet.DialIPC(ctx)
	require.NoError(t, err, "dial ZET IPC pipe")
	t.Cleanup(func() { _ = client.Close() })

	identityName := identityNameFor(t)
	controllerURL := overlay.ControllerHostPort()
	identityData := testutil.AddIdentityData{
		IdentityFilename: identityName,
		ControllerURL:    &controllerURL,
	}

	t.Logf("sending URL AddIdentity for %q with ControllerURL=%s", identityName, controllerURL)
	resp, err := client.AddIdentity(ctx, identityData)
	require.NoError(t, err, "URL AddIdentity send\n%s", zet.Logs())
	require.True(t, resp.Success, "URL AddIdentity failed: error=%q code=%d\n%s", resp.Error, resp.Code, zet.Logs())
	t.Logf("URL AddIdentity succeeded for %q", identityName)

	t.Logf("fetching tunnel status to verify identity file")
	status, err := client.GetTunnelStatus(ctx)
	require.NoError(t, err, "Status after URL AddIdentity\n%s", zet.Logs())
	entry := status.FindIdentity(identityName)
	require.NotNil(t, entry, "identity %q not found in Status after URL AddIdentity", identityName)
	info, err := os.Stat(entry.Identifier)
	require.NoError(t, err, "identity file should be written to -I dir")
	require.Greater(t, info.Size(), int64(0), "identity file should be non-empty")
	t.Logf("found %q in status; URL-enrolled identity file written: %s (%d bytes)", identityName, entry.Identifier, info.Size())
}

func testUrlEnrollmentSameNameTwiceSecondFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := zet.DialIPC(ctx)
	require.NoError(t, err, "dial ZET IPC pipe")
	t.Cleanup(func() { _ = client.Close() })

	identityName := identityNameFor(t)
	controllerURL := overlay.ControllerHostPort()
	identityData := testutil.AddIdentityData{
		IdentityFilename: identityName,
		ControllerURL:    &controllerURL,
	}

	t.Logf("sending first URL AddIdentity for %q", identityName)
	first, err := client.AddIdentity(ctx, identityData)
	require.NoError(t, err, "first URL AddIdentity send\n%s", zet.Logs())
	require.True(t, first.Success, "first URL AddIdentity should succeed: error=%q\n%s", first.Error, zet.Logs())
	t.Logf("first URL AddIdentity succeeded for %q", identityName)

	t.Logf("sending duplicate URL AddIdentity for %q", identityName)
	second, err := client.AddIdentity(ctx, identityData)
	require.NoError(t, err, "second URL AddIdentity send\n%s", zet.Logs())
	require.False(t, second.Success, "second URL AddIdentity should fail, got Success=true")
	require.Contains(t, second.Error, "identity exists",
		"expected duplicate-name error, got %q", second.Error)
	t.Logf("second URL AddIdentity correctly rejected: %s", second.Error)
}

func testUrlEnrollmentAfterJwtSameNameFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	identityName := identityNameFor(t)
	t.Logf("minting JWT for %q", identityName)
	jwt, err := overlay.CreateIdentityJWT(ctx, identityName)
	require.NoError(t, err, "mint JWT via overlay")
	require.NotEmpty(t, jwt)

	client, err := zet.DialIPC(ctx)
	require.NoError(t, err, "dial ZET IPC pipe")
	t.Cleanup(func() { _ = client.Close() })

	jwtIdentityData := testutil.AddIdentityData{
		IdentityFilename: identityName,
		JwtContent:       &jwt,
	}
	t.Logf("sending JWT AddIdentity for %q", identityName)
	first, err := client.AddIdentity(ctx, jwtIdentityData)
	require.NoError(t, err, "first JWT AddIdentity send\n%s", zet.Logs())
	require.True(t, first.Success, "first JWT AddIdentity should succeed: error=%q\n%s", first.Error, zet.Logs())
	t.Logf("JWT AddIdentity succeeded for %q", identityName)

	controllerURL := overlay.ControllerHostPort()
	urlIdentityData := testutil.AddIdentityData{
		IdentityFilename: identityName,
		ControllerURL:    &controllerURL,
	}
	t.Logf("sending URL AddIdentity with same name %q (should be rejected as duplicate)", identityName)
	second, err := client.AddIdentity(ctx, urlIdentityData)
	require.NoError(t, err, "second URL AddIdentity send\n%s", zet.Logs())
	require.False(t, second.Success, "URL AddIdentity should fail when name already enrolled via JWT, got Success=true")
	require.Contains(t, second.Error, "identity exists", "expected duplicate-name error, got %q", second.Error)
	t.Logf("URL AddIdentity correctly rejected after JWT enroll: %s", second.Error)
}

func testUrlEnrollmentWithNonZitiEndpointFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := zet.DialIPC(ctx)
	require.NoError(t, err, "dial ZET IPC pipe")
	t.Cleanup(func() { _ = client.Close() })

	identityName := identityNameFor(t)
	nonZitiURL := "https://example.com"
	identityData := testutil.AddIdentityData{
		IdentityFilename: identityName,
		ControllerURL:    &nonZitiURL,
	}

	t.Logf("sending URL AddIdentity for %q with non-Ziti URL=%s", identityName, nonZitiURL)
	resp, err := client.AddIdentity(ctx, identityData)
	require.NoError(t, err, "URL AddIdentity send\n%s", zet.Logs())
	require.False(t, resp.Success, "non-Ziti URL %q should be rejected, got Success=true\n%s", nonZitiURL, zet.Logs())
	t.Logf("non-Ziti URL correctly rejected: code=%d error=%q", resp.Code, resp.Error)
}

func testUrlEnrollmentWithMalformedUrlFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := zet.DialIPC(ctx)
	require.NoError(t, err, "dial ZET IPC pipe")
	t.Cleanup(func() { _ = client.Close() })

	identityName := identityNameFor(t)
	badURL := "not-a-url"
	identityData := testutil.AddIdentityData{
		IdentityFilename: identityName,
		ControllerURL:    &badURL,
	}

	t.Logf("sending URL AddIdentity for %q with malformed URL=%q", identityName, badURL)
	resp, err := client.AddIdentity(ctx, identityData)
	require.NoError(t, err, "URL AddIdentity send\n%s", zet.Logs())
	require.False(t, resp.Success, "malformed URL %q should be rejected, got Success=true\n%s", badURL, zet.Logs())
	t.Logf("malformed URL correctly rejected: code=%d error=%q", resp.Code, resp.Error)
}
