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
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/openziti/ziti-tunnel-sdk-c/tests/integration/testutil"
	"github.com/stretchr/testify/require"
)

func TestUrlEnrollment(t *testing.T) {
	requireUrlEnrollmentPrecondition(t)
	t.Run("withValidControllerUrlSucceeds", testUrlEnrollmentWithValidControllerUrlSucceeds)
	t.Run("withMalformedUrlFails", testUrlEnrollmentWithMalformedUrlFails)
	t.Run("sameNameTwiceSecondFails", testUrlEnrollmentSameNameTwiceSecondFails)
}

func requireUrlEnrollmentPrecondition(t *testing.T) {
	t.Helper()
	hostport := fmt.Sprintf("localhost:%d", overlay.ControllerPort)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", hostport, nil)
	if err != nil {
		caPath := filepath.Join(overlayHome, "pki", "root-ca", "certs", "root-ca.cert")
		var install, cleanup string
		switch runtime.GOOS {
		case "windows":
			install = fmt.Sprintf(`Import-Certificate -FilePath "%s" -CertStoreLocation Cert:\LocalMachine\Root`, caPath)
			cleanup = fmt.Sprintf(`$c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 "%s"; Get-ChildItem Cert:\LocalMachine\Root | ? Thumbprint -eq $c.Thumbprint | Remove-Item`, caPath)
		case "darwin":
			install = fmt.Sprintf(`sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s`, caPath)
			cleanup = fmt.Sprintf(`sudo security delete-certificate -Z $(openssl x509 -in %s -noout -fingerprint -sha1 | sed 's/.*=//' | tr -d ':') /Library/Keychains/System.keychain`, caPath)
		case "linux":
			install = fmt.Sprintf(`sudo cp %s /usr/local/share/ca-certificates/ziti-test.crt && sudo update-ca-certificates`, caPath)
			cleanup = `sudo rm /usr/local/share/ca-certificates/ziti-test.crt && sudo update-ca-certificates --fresh`
		default:
			t.Skipf("URL tests need the CA at %s in OS trust (no install instructions for %s)", caPath, runtime.GOOS)
			return
		}
		t.Skipf(`URL tests need the test overlay's CA in OS trust.

  Install:
  %s

  Cleanup when done:
  %s`, install, cleanup)
	}
	_ = conn.Close()
}

// testUrlEnrollmentWithValidControllerUrlSucceeds exercises the "URL + no enroll-to mode" path.
func testUrlEnrollmentWithValidControllerUrlSucceeds(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := testutil.DialIPC(ctx)
	require.NoError(t, err, "dial ZET IPC pipe")
	t.Cleanup(func() { _ = client.Close() })

	identityName := identityNameFor(t)
	controllerURL := overlay.ControllerHostPort()
	identityData := testutil.AddIdentityData{
		IdentityFilename: identityName,
		ControllerURL:    &controllerURL,
	}

	resp, err := client.AddIdentity(ctx, identityData)
	require.NoError(t, err, "URL AddIdentity send\n%s", zet.Logs())
	require.True(t, resp.Success, "URL AddIdentity failed: error=%q code=%d\n%s", resp.Error, resp.Code, zet.Logs())

	status, err := client.GetTunnelStatus(ctx)
	require.NoError(t, err, "Status after URL AddIdentity\n%s", zet.Logs())
	entry := status.FindIdentity(identityName)
	require.NotNil(t, entry, "identity %q not found in Status after URL AddIdentity", identityName)
	info, err := os.Stat(entry.Identifier)
	require.NoError(t, err, "identity file should be written to -I dir")
	require.Greater(t, info.Size(), int64(0), "identity file should be non-empty")
	t.Logf("URL-enrolled identity file written: %s (%d bytes)", entry.Identifier, info.Size())
}

func testUrlEnrollmentSameNameTwiceSecondFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := testutil.DialIPC(ctx)
	require.NoError(t, err, "dial ZET IPC pipe")
	t.Cleanup(func() { _ = client.Close() })

	identityName := identityNameFor(t)
	controllerURL := overlay.ControllerHostPort()
	identityData := testutil.AddIdentityData{
		IdentityFilename: identityName,
		ControllerURL:    &controllerURL,
	}

	first, err := client.AddIdentity(ctx, identityData)
	require.NoError(t, err, "first URL AddIdentity send\n%s", zet.Logs())
	require.True(t, first.Success, "first URL AddIdentity should succeed: error=%q\n%s", first.Error, zet.Logs())

	second, err := client.AddIdentity(ctx, identityData)
	require.NoError(t, err, "second URL AddIdentity send\n%s", zet.Logs())
	require.False(t, second.Success, "second URL AddIdentity should fail, got Success=true")
	require.Contains(t, second.Error, "identity exists",
		"expected duplicate-name error, got %q", second.Error)
	t.Logf("second URL AddIdentity correctly rejected: %s", second.Error)
}

func testUrlEnrollmentWithMalformedUrlFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := testutil.DialIPC(ctx)
	require.NoError(t, err, "dial ZET IPC pipe")
	t.Cleanup(func() { _ = client.Close() })

	identityName := identityNameFor(t)
	badURL := "not-a-url"
	identityData := testutil.AddIdentityData{
		IdentityFilename: identityName,
		ControllerURL:    &badURL,
	}

	resp, err := client.AddIdentity(ctx, identityData)
	require.NoError(t, err, "URL AddIdentity send\n%s", zet.Logs())
	require.False(t, resp.Success, "malformed URL %q should be rejected, got Success=true\n%s", badURL, zet.Logs())
	t.Logf("malformed URL correctly rejected: code=%d error=%q", resp.Code, resp.Error)
}
