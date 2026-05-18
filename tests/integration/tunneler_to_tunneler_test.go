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
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/openziti/ziti-tunnel-sdk-c/tests/integration/testutil"
	"github.com/stretchr/testify/require"
)

// TestTunnelerToTunnelerTCP exercises the TCP data plane with two run-mode ZETs.
// One ZET intercepts the client-side TCP connection; the other hosts the service
// and forwards to a local echo backend.
//
// Requires root/CAP_NET_ADMIN — both ZETs open TUN devices.
func TestTunnelerToTunnelerTCP(t *testing.T) {
	t.Run("zetA_intercepts_zetB_hosts", func(t *testing.T) {
		testT2TTCP(t, zet, zetB, "100.64.0.10", 21000)
	})
	t.Run("zetB_intercepts_zetA_hosts", func(t *testing.T) {
		testT2TTCP(t, zetB, zet, "100.128.0.10", 21001)
	})
}

// TestTunnelerToTunnelerUDP exercises the UDP data plane with two run-mode ZETs.
//
// Requires root/CAP_NET_ADMIN — both ZETs open TUN devices.
func TestTunnelerToTunnelerUDP(t *testing.T) {
	t.Run("zetA_intercepts_zetB_hosts", func(t *testing.T) {
		testT2TUDP(t, zet, zetB, "100.64.0.11", 22000)
	})
	t.Run("zetB_intercepts_zetA_hosts", func(t *testing.T) {
		testT2TUDP(t, zetB, zet, "100.128.0.11", 22001)
	})
}

// testT2TTCP runs a TCP echo end-to-end test:
//   - interceptZET intercepts connections to interceptIP:interceptPort
//   - hostZET hosts the service and forwards to a local TCP echo server
func testT2TTCP(t *testing.T, interceptZET, hostZET *testutil.ZET, interceptIP string, interceptPort int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	echo := testutil.StartTCPEcho(t)
	_, echoPort, err := net.SplitHostPort(echo.Addr)
	require.NoError(t, err, "failed to parse echo address")
	echoPortInt := 0
	fmt.Sscanf(echoPort, "%d", &echoPortInt)
	t.Logf("started local TCP echo backend at %s", echo.Addr)

	names := t2tNames(t)
	setupT2TService(t, ctx, interceptZET, hostZET, names, "tcp", "127.0.0.1", echoPortInt, interceptIP, interceptPort)

	interceptAddr := net.JoinHostPort(interceptIP, fmt.Sprintf("%d", interceptPort))

	// Retry the dial until the service is ready on both sides (intercept route
	// installed and host terminator active) or context expires.
	waitCtx, waitCancel := context.WithTimeout(ctx, 30*time.Second)
	defer waitCancel()
	waitForTCPService(t, waitCtx, interceptAddr, interceptZET, hostZET)

	// Dial and echo.
	t.Logf("dialing intercepted TCP addr %s", interceptAddr)
	conn, err := net.DialTimeout("tcp", interceptAddr, 10*time.Second)
	require.NoError(t, err, "failed to dial intercepted address %s\ninterceptZET: %s\nhostZET: %s",
		interceptAddr, interceptZET.Logs(), hostZET.Logs())
	defer conn.Close()
	t.Logf("TCP connection established to %s", interceptAddr)

	payload := []byte("hello-ziti-tcp")
	t.Logf("writing TCP payload (%d bytes)", len(payload))
	_, err = conn.Write(payload)
	require.NoError(t, err, "failed to write payload\ninterceptZET: %s\nhostZET: %s", interceptZET.Logs(), hostZET.Logs())

	t.Logf("reading TCP echo response")
	got := make([]byte, len(payload))
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, err = readFull(conn, got)
	require.NoError(t, err, "failed to read echo\ninterceptZET: %s\nhostZET: %s", interceptZET.Logs(), hostZET.Logs())
	require.Equal(t, payload, got, "TCP echo mismatch\ninterceptZET: %s\nhostZET: %s", interceptZET.Logs(), hostZET.Logs())
	t.Logf("TCP echo round-trip succeeded: payload=%q got=%q", payload, got)
}

// testT2TUDP runs a UDP echo end-to-end test.
func testT2TUDP(t *testing.T, interceptZET, hostZET *testutil.ZET, interceptIP string, interceptPort int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	echo := testutil.StartUDPEcho(t)
	_, echoPort, err := net.SplitHostPort(echo.Addr)
	require.NoError(t, err, "failed to parse echo address")
	echoPortInt := 0
	fmt.Sscanf(echoPort, "%d", &echoPortInt)
	t.Logf("started local UDP echo backend at %s", echo.Addr)

	names := t2tNames(t)
	setupT2TService(t, ctx, interceptZET, hostZET, names, "udp", "127.0.0.1", echoPortInt, interceptIP, interceptPort)

	interceptAddr := net.JoinHostPort(interceptIP, fmt.Sprintf("%d", interceptPort))

	// Retry until the UDP intercept route and host terminator are active.
	waitCtx, waitCancel := context.WithTimeout(ctx, 30*time.Second)
	defer waitCancel()
	waitForUDPService(t, waitCtx, interceptAddr, interceptZET, hostZET)

	// Dial and echo.
	t.Logf("dialing intercepted UDP addr %s", interceptAddr)
	conn, err := net.Dial("udp", interceptAddr)
	require.NoError(t, err, "failed to dial intercepted UDP address %s", interceptAddr)
	defer conn.Close()

	payload := []byte("hello-ziti-udp")
	t.Logf("writing UDP payload (%d bytes)", len(payload))
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, err = conn.Write(payload)
	require.NoError(t, err, "failed to write UDP payload\ninterceptZET: %s\nhostZET: %s", interceptZET.Logs(), hostZET.Logs())

	t.Logf("reading UDP echo response")
	got := make([]byte, len(payload))
	_, err = conn.Read(got)
	require.NoError(t, err, "failed to read UDP echo\ninterceptZET: %s\nhostZET: %s", interceptZET.Logs(), hostZET.Logs())
	require.Equal(t, payload, got, "UDP echo mismatch\ninterceptZET: %s\nhostZET: %s", interceptZET.Logs(), hostZET.Logs())
	t.Logf("UDP echo round-trip succeeded: payload=%q got=%q", payload, got)
}

// t2tResourceNames holds all the controller-side resource names for a single t2t test scenario.
type t2tResourceNames struct {
	interceptIdentity string
	hostIdentity      string
	hostConfig        string
	interceptConfig   string
	service           string
	bindPolicy        string
	dialPolicy        string
}

func t2tNames(t *testing.T) t2tResourceNames {
	base := strings.ReplaceAll(t.Name(), "/", "-")
	return t2tResourceNames{
		interceptIdentity: base + "-intercept-id",
		hostIdentity:      base + "-host-id",
		hostConfig:        base + "-host-cfg",
		interceptConfig:   base + "-intercept-cfg",
		service:           base + "-svc",
		bindPolicy:        base + "-bind",
		dialPolicy:        base + "-dial",
	}
}

// setupT2TService creates controller-side resources and enrolls identities into each ZET.
// Cleanup removes all resources at the end of the test.
func setupT2TService(
	t *testing.T,
	ctx context.Context,
	interceptZET, hostZET *testutil.ZET,
	names t2tResourceNames,
	protocol, forwardAddr string,
	forwardPort int,
	interceptIP string,
	interceptPort int,
) {
	t.Helper()

	// Mint identities.
	t.Logf("creating JWT for intercept identity %q", names.interceptIdentity)
	interceptJWT, err := overlay.CreateIdentityJWT(ctx, names.interceptIdentity)
	require.NoError(t, err, "failed to create intercept identity JWT")
	t.Logf("creating JWT for host identity %q", names.hostIdentity)
	hostJWT, err := overlay.CreateIdentityJWT(ctx, names.hostIdentity)
	require.NoError(t, err, "failed to create host identity JWT")

	// Enroll identities into their respective ZETs.
	interceptClient := testutil.OpenCommandPipe(t, ctx, interceptZET)
	hostClient := testutil.OpenCommandPipe(t, ctx, hostZET)

	interceptIdentityData := testutil.AddIdentityData{
		IdentityFilename: names.interceptIdentity,
		JwtContent:       &interceptJWT,
	}
	resp := testutil.Enroll(t, ctx, interceptClient, interceptIdentityData)
	require.True(t, resp.Success, "AddIdentity to intercept ZET failed: %s\n%s", resp.Error, interceptZET.Logs())

	hostIdentityData := testutil.AddIdentityData{
		IdentityFilename: names.hostIdentity,
		JwtContent:       &hostJWT,
	}
	resp = testutil.Enroll(t, ctx, hostClient, hostIdentityData)
	require.True(t, resp.Success, "AddIdentity to host ZET failed: %s\n%s", resp.Error, hostZET.Logs())

	// Create controller-side resources.
	t.Logf("creating host config %q (forward to %s:%d via %s)", names.hostConfig, forwardAddr, forwardPort, protocol)
	require.NoError(t, overlay.CreateHostConfigV1(ctx, names.hostConfig, protocol, forwardAddr, forwardPort),
		"create host config")
	t.Logf("creating intercept config %q (intercept %s:%d via %s)", names.interceptConfig, interceptIP, interceptPort, protocol)
	require.NoError(t, overlay.CreateInterceptConfigV1(ctx, names.interceptConfig,
		[]string{protocol}, []string{interceptIP + "/32"}, interceptPort, interceptPort),
		"create intercept config")
	t.Logf("creating service %q binding both configs", names.service)
	require.NoError(t, overlay.CreateService(ctx, names.service,
		[]string{names.hostConfig, names.interceptConfig}),
		"create service")
	t.Logf("creating bind service policy %q allowing %q to host %q", names.bindPolicy, names.hostIdentity, names.service)
	require.NoError(t, overlay.CreateBindServicePolicy(ctx, names.bindPolicy, names.hostIdentity, names.service),
		"create bind policy")
	t.Logf("creating dial service policy %q allowing %q to dial %q", names.dialPolicy, names.interceptIdentity, names.service)
	require.NoError(t, overlay.CreateDialServicePolicy(ctx, names.dialPolicy, names.interceptIdentity, names.service),
		"create dial policy")
	t.Logf("controller-side setup complete")

	// Cleanup: remove identities and controller-side resources at test end.
	cleanupCtx := context.Background()
	t.Cleanup(func() {
		_, _ = interceptClient.RemoveIdentity(cleanupCtx, names.interceptIdentity)
		_, _ = hostClient.RemoveIdentity(cleanupCtx, names.hostIdentity)
		_ = overlay.DeleteServicePolicy(cleanupCtx, names.dialPolicy)
		_ = overlay.DeleteServicePolicy(cleanupCtx, names.bindPolicy)
		_ = overlay.DeleteService(cleanupCtx, names.service)
		_ = overlay.DeleteConfig(cleanupCtx, names.interceptConfig)
		_ = overlay.DeleteConfig(cleanupCtx, names.hostConfig)
	})
}

// waitForTCPService polls by attempting a TCP connection until it succeeds or ctx expires.
// A successful connect proves the intercept route is installed and the host terminator is active.
func waitForTCPService(t *testing.T, ctx context.Context, addr string, interceptZET, hostZET *testutil.ZET) {
	t.Helper()
	t.Logf("polling for TCP service readiness at %s", addr)
	attempts := 0
	for {
		attempts++
		conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
		if err == nil {
			conn.Close()
			t.Logf("TCP service at %s became ready after %d attempt(s)", addr, attempts)
			return
		}
		if attempts == 1 || attempts%5 == 0 {
			t.Logf("TCP service at %s still not ready after %d attempt(s): %v", addr, attempts, err)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("service at %s never became ready after %d attempt(s): %v\ninterceptZET: %s\nhostZET: %s",
				addr, attempts, ctx.Err(), interceptZET.Logs(), hostZET.Logs())
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// waitForUDPService polls by sending a probe datagram until it is echoed back or ctx expires.
func waitForUDPService(t *testing.T, ctx context.Context, addr string, interceptZET, hostZET *testutil.ZET) {
	t.Helper()
	t.Logf("polling for UDP service readiness at %s", addr)
	probe := []byte("probe")
	attempts := 0
	for {
		attempts++
		conn, err := net.Dial("udp", addr)
		if err != nil {
			if attempts == 1 || attempts%5 == 0 {
				t.Logf("UDP dial to %s still failing after %d attempt(s): %v", addr, attempts, err)
			}
			select {
			case <-ctx.Done():
				t.Fatalf("UDP service at %s never became ready after %d attempt(s): %v\ninterceptZET: %s\nhostZET: %s",
					addr, attempts, ctx.Err(), interceptZET.Logs(), hostZET.Logs())
			case <-time.After(500 * time.Millisecond):
			}
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(1 * time.Second))
		_, _ = conn.Write(probe)
		buf := make([]byte, len(probe))
		_, err = conn.Read(buf)
		conn.Close()
		if err == nil && bytes.Equal(buf, probe) {
			t.Logf("UDP service at %s became ready after %d attempt(s)", addr, attempts)
			return
		}
		if attempts == 1 || attempts%5 == 0 {
			t.Logf("UDP probe to %s not echoed after %d attempt(s): err=%v got=%q", addr, attempts, err, buf)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("UDP service at %s never became ready after %d attempt(s): %v\ninterceptZET: %s\nhostZET: %s",
				addr, attempts, ctx.Err(), interceptZET.Logs(), hostZET.Logs())
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// readFull reads exactly len(buf) bytes from conn, handling short reads.
func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
