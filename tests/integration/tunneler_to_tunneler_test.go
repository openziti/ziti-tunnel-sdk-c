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

// requireMultiTunnel skips when either ZET predates multi-tunnel support
func requireMultiTunnel(t *testing.T) {
	if state.zetClient.SupportsMultiTunnel() && state.zetHost.SupportsMultiTunnel() {
		return
	}
	t.Skipf("multi-tunnel requires ZET >= 1.17.0; zetA=%s zetB=%s", state.zetClient.Version, state.zetHost.Version)
}

// TestTunnelerToTunnelerTCP exercises the TCP data plane with two run-mode ZETs.
// One ZET intercepts the client-side TCP connection; the other hosts the service
// and forwards to a local echo backend.
//
// Requires root/CAP_NET_ADMIN — both ZETs open TUN devices.
func TestTunnelerToTunnelerTCP(t *testing.T) {
	requireMultiTunnel(t)
	t.Run("zetA_intercepts_zetB_hosts", func(t *testing.T) {
		testT2TTCP(t, state.zetClient, state.zetHost, "100.64.0.10", 21000)
	})
	t.Run("zetB_intercepts_zetA_hosts", func(t *testing.T) {
		testT2TTCP(t, state.zetHost, state.zetClient, "100.128.0.10", 21001)
	})
}

// TestTunnelerToTunnelerUDP exercises the UDP data plane with two run-mode ZETs.
//
// Requires root/CAP_NET_ADMIN — both ZETs open TUN devices.
func TestTunnelerToTunnelerUDP(t *testing.T) {
	requireMultiTunnel(t)
	t.Run("zetA_intercepts_zetB_hosts", func(t *testing.T) {
		testT2TUDP(t, state.zetClient, state.zetHost, "100.64.0.11", 22000)
	})
	t.Run("zetB_intercepts_zetA_hosts", func(t *testing.T) {
		testT2TUDP(t, state.zetHost, state.zetClient, "100.128.0.11", 22001)
	})
}

// testT2TTCP runs a TCP echo end-to-end test:
//   - interceptZET intercepts connections to interceptIP:interceptPort
//   - hostZET hosts the service and forwards to a local TCP echo server
func testT2TTCP(t *testing.T, interceptZET, hostZET *testutil.ZET, interceptIP string, interceptPort int) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	echo := testutil.StartTCPEcho(t)
	_, echoPort, err := net.SplitHostPort(echo.Addr)
	require.NoError(t, err, "parse echo addr")
	echoPortInt := 0
	fmt.Sscanf(echoPort, "%d", &echoPortInt)

	names := t2tNames(t)
	setupT2TService(t, ctx, interceptZET, hostZET, names, "tcp", "127.0.0.1", echoPortInt, interceptIP, interceptPort)

	interceptAddr := net.JoinHostPort(interceptIP, fmt.Sprintf("%d", interceptPort))

	// Retry the dial until the service is ready on both sides (intercept route
	// installed and host terminator active) or context expires.
	waitCtx, waitCancel := context.WithTimeout(ctx, 30*time.Second)
	defer waitCancel()
	waitForTCPService(t, waitCtx, interceptAddr, interceptZET, hostZET)

	// Dial and echo.
	conn, err := net.DialTimeout("tcp", interceptAddr, 10*time.Second)
	require.NoError(t, err, "dial intercepted addr %s\ninterceptZET: %s\nhostZET: %s",
		interceptAddr, interceptZET.LogFile(), hostZET.LogFile())
	defer conn.Close()

	payload := []byte("hello-ziti-tcp")
	_, err = conn.Write(payload)
	require.NoError(t, err, "write payload\ninterceptZET: %s\nhostZET: %s", interceptZET.LogFile(), hostZET.LogFile())

	got := make([]byte, len(payload))
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, err = readFull(conn, got)
	require.NoError(t, err, "read echo\ninterceptZET: %s\nhostZET: %s", interceptZET.LogFile(), hostZET.LogFile())
	require.Equal(t, payload, got, "TCP echo mismatch\ninterceptZET: %s\nhostZET: %s", interceptZET.LogFile(), hostZET.LogFile())
}

// testT2TUDP runs a UDP echo end-to-end test.
func testT2TUDP(t *testing.T, interceptZET, hostZET *testutil.ZET, interceptIP string, interceptPort int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	echo := testutil.StartUDPEcho(t)
	_, echoPort, err := net.SplitHostPort(echo.Addr)
	require.NoError(t, err, "parse echo addr")
	echoPortInt := 0
	fmt.Sscanf(echoPort, "%d", &echoPortInt)

	names := t2tNames(t)
	setupT2TService(t, ctx, interceptZET, hostZET, names, "udp", "127.0.0.1", echoPortInt, interceptIP, interceptPort)

	interceptAddr := net.JoinHostPort(interceptIP, fmt.Sprintf("%d", interceptPort))

	// Retry until the UDP intercept route and host terminator are active.
	waitCtx, waitCancel := context.WithTimeout(ctx, 30*time.Second)
	defer waitCancel()
	waitForUDPService(t, waitCtx, interceptAddr, interceptZET, hostZET)

	// Dial and echo.
	conn, err := net.Dial("udp", interceptAddr)
	require.NoError(t, err, "dial intercepted UDP addr %s", interceptAddr)
	defer conn.Close()

	payload := []byte("hello-ziti-udp")
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, err = conn.Write(payload)
	require.NoError(t, err, "write UDP payload\ninterceptZET: %s\nhostZET: %s", interceptZET.LogFile(), hostZET.LogFile())

	got := make([]byte, len(payload))
	_, err = conn.Read(got)
	require.NoError(t, err, "read UDP echo\ninterceptZET: %s\nhostZET: %s", interceptZET.LogFile(), hostZET.LogFile())
	require.Equal(t, payload, got, "UDP echo mismatch\ninterceptZET: %s\nhostZET: %s", interceptZET.LogFile(), hostZET.LogFile())
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

	overlay := state.overlay
	// Mint identities.
	interceptJWT, err := overlay.CreateIdentityJWT(names.interceptIdentity)
	require.NoError(t, err, "create intercept identity JWT")
	hostJWT, err := overlay.CreateIdentityJWT(names.hostIdentity)
	require.NoError(t, err, "create host identity JWT")

	// Enroll identities into their respective ZETs.
	interceptClient, err := interceptZET.DialIPC()
	require.NoError(t, err, "dial intercept ZET IPC")
	t.Cleanup(func() { _ = interceptClient.Close() })

	hostClient, err := hostZET.DialIPC()
	require.NoError(t, err, "dial host ZET IPC")
	t.Cleanup(func() { _ = hostClient.Close() })

	resp := interceptClient.AddIdentity(t, testutil.AddIdentityData{
		IdentityFilename: names.interceptIdentity,
		JwtContent:       &interceptJWT,
	})
	require.True(t, resp.Success(), "AddIdentity to intercept ZET failed: %s\n%s", resp.Error, interceptZET.LogFile())

	resp = hostClient.AddIdentity(t, testutil.AddIdentityData{
		IdentityFilename: names.hostIdentity,
		JwtContent:       &hostJWT,
	})
	require.True(t, resp.Success(), "AddIdentity to host ZET failed: %s\n%s", resp.Error, hostZET.LogFile())

	// Create controller-side resources.
	require.NoError(t, overlay.CreateHostConfigV1(names.hostConfig, protocol, forwardAddr, forwardPort),
		"create host config")
	require.NoError(t, overlay.CreateInterceptConfigV1(names.interceptConfig,
		[]string{protocol}, []string{interceptIP + "/32"}, interceptPort, interceptPort),
		"create intercept config")
	require.NoError(t, overlay.CreateService(names.service,
		[]string{names.hostConfig, names.interceptConfig}),
		"create service")
	require.NoError(t, overlay.CreateBindServicePolicy(names.bindPolicy, names.hostIdentity, names.service),
		"create bind policy")
	require.NoError(t, overlay.CreateDialServicePolicy(names.dialPolicy, names.interceptIdentity, names.service),
		"create dial policy")

	// Cleanup: remove identities and controller-side resources at test end.
	t.Cleanup(func() {
		interceptClient.RemoveIdentity(t, names.interceptIdentity)
		hostClient.RemoveIdentity(t, names.hostIdentity)
		_ = overlay.DeleteServicePolicy(names.dialPolicy)
		_ = overlay.DeleteServicePolicy(names.bindPolicy)
		_ = overlay.DeleteService(names.service)
		_ = overlay.DeleteConfig(names.interceptConfig)
		_ = overlay.DeleteConfig(names.hostConfig)
	})
}

// waitForTCPService polls by attempting a TCP connection until it succeeds or ctx expires.
// A successful connect proves the intercept route is installed and the host terminator is active.
func waitForTCPService(t *testing.T, ctx context.Context, addr string, interceptZET, hostZET *testutil.ZET) {
	t.Helper()
	for {
		conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
		if err == nil {
			conn.Close()
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("service at %s never became ready: %v\ninterceptZET: %s\nhostZET: %s",
				addr, ctx.Err(), interceptZET.LogFile(), hostZET.LogFile())
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// waitForUDPService polls by sending a probe datagram until it is echoed back or ctx expires.
func waitForUDPService(t *testing.T, ctx context.Context, addr string, interceptZET, hostZET *testutil.ZET) {
	t.Helper()
	probe := []byte("probe")
	for {
		conn, err := net.Dial("udp", addr)
		if err != nil {
			select {
			case <-ctx.Done():
				t.Fatalf("UDP service at %s never became ready: %v\ninterceptZET: %s\nhostZET: %s",
					addr, ctx.Err(), interceptZET.LogFile(), hostZET.LogFile())
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
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("UDP service at %s never became ready: %v\ninterceptZET: %s\nhostZET: %s",
				addr, ctx.Err(), interceptZET.LogFile(), hostZET.LogFile())
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
