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

// Resource-leak regression tests for the L3 data path.
//
// Each test runs a data-path workload in a loop, then uses LeakHarness to assert
// that lwIP pool counters, ziti connection counts, open FD counts, and process
// RSS return to their pre-workload baseline on both the intercepting and hosting
// tunnelers. This gives confidence that a data-path refactor has not introduced
// per-connection resource leaks.
//
// Intercept IP/port allocations — zetA intercepts, zetB hosts, using 100.64.0.x
// (outside either ZET's own DNS range). Existing allocations (do not reuse):
//
//	100.64.0.10:21000  TestTunnelerToTunnelerTCP/zetA_intercepts_zetB_hosts
//	100.64.0.11:22000  TestTunnelerToTunnelerUDP/zetA_intercepts_zetB_hosts
//	100.128.0.10:21001 TestTunnelerToTunnelerTCP/zetB_intercepts_zetA_hosts
//	100.128.0.11:22001 TestTunnelerToTunnelerUDP/zetB_intercepts_zetA_hosts
//
// Leak test allocations:
//
//	100.64.0.20:23000  TestLeak_TCPTinyEcho
//	100.64.0.21:23001  TestLeak_TCPLargeTransfer
//	100.64.0.22:24000  TestLeak_UDPDatagram
//	100.64.0.23:25000  TestLeak_TCPConcurrentFanout

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openziti/ziti-tunnel-sdk-c/tests/integration/testutil"
	"github.com/stretchr/testify/require"
)

var (
	tcpLeakPools  = []string{"MEMP_PBUF_POOL", "MEMP_TCP_PCB"}
	udpLeakPools  = []string{"MEMP_PBUF_POOL", "MEMP_UDP_PCB"}
	leakZETSeq    atomic.Int32
)

// startLeakZETs starts a fresh, dedicated ZET pair for a single TestLeak_* test.
// Each test gets its own processes so that LSan (when enabled) can report leaks
// with per-test attribution. Discriminators are lkA<n>/lkB<n> to avoid conflicts
// with the shared zetA/zetB. DNS ranges 100.96.0.0/16 and 100.97.0.0/16 are
// reserved for these transient instances and must not overlap with intercept IPs
// used in the TestLeak_* address table above.
// Stop() + CheckLsanLeaks() are registered as t.Cleanup, so they run after harness.Run().
func startLeakZETs(t *testing.T) (interceptZET, hostZET *testutil.ZET) {
	t.Helper()
	n := int(leakZETSeq.Add(1))
	discA := fmt.Sprintf("lkA%d", n)
	discB := fmt.Sprintf("lkB%d", n)
	rootBase := filepath.Join(os.TempDir(), "zet-leak", t.Name())

	interceptZET = &testutil.ZET{
		BinPath:       state.zetClient.BinPath,
		Discriminator: discA,
		DNSRange:      "100.96.0.1/16",
		RootDir:       filepath.Join(rootBase, discA),
		Verbosity:     state.zetClient.Verbosity,
		LsanEnabled:   lsanEnabled,
	}
	hostZET = &testutil.ZET{
		BinPath:       state.zetHost.BinPath,
		Discriminator: discB,
		DNSRange:      "100.97.0.1/16",
		RootDir:       filepath.Join(rootBase, discB),
		Verbosity:     state.zetHost.Verbosity,
		LsanEnabled:   lsanEnabled,
	}

	require.NoError(t, interceptZET.Start(), "start intercept leak ZET")
	t.Cleanup(func() {
		interceptZET.Stop()
		interceptZET.CheckLsanLeaks(t)
	})

	require.NoError(t, hostZET.Start(), "start host leak ZET")
	t.Cleanup(func() {
		hostZET.Stop()
		hostZET.CheckLsanLeaks(t)
	})

	return interceptZET, hostZET
}

// TestLeak_TCPTinyEcho iterates 100 connect/echo/close cycles over a TCP
// service and asserts no lwIP, ziti, FD, or RSS leaks after settle.
//
// Requires root/CAP_NET_ADMIN.
func TestLeak_TCPTinyEcho(t *testing.T) {
	const (
		iterations    = 100
		interceptIP   = "100.64.0.20"
		interceptPort = 23000
	)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	interceptZET, hostZET := startLeakZETs(t)
	echo := testutil.StartTCPEcho(t)
	names := t2tNames(t)
	setupT2TService(t, ctx, interceptZET, hostZET, names,
		"tcp", "127.0.0.1", addrPort(t, echo.Addr), interceptIP, interceptPort)

	interceptAddr := net.JoinHostPort(interceptIP, fmt.Sprintf("%d", interceptPort))
	waitCtx, waitCancel := context.WithTimeout(ctx, 30*time.Second)
	defer waitCancel()
	waitForTCPService(t, waitCtx, interceptAddr, interceptZET, hostZET)

	harness := testutil.NewLeakHarness(t,
		[]*testutil.ZET{interceptZET, hostZET}, tcpLeakPools)
	payload := []byte("hello-ziti-leak-tcp")

	harness.Run(t, func() {
		for i := range iterations {
			conn, err := net.DialTimeout("tcp", interceptAddr, 10*time.Second)
			require.NoError(t, err, "iter %d: dial\ninterceptZET: %s\nhostZET: %s",
				i, state.zetClient.LogFile(), state.zetHost.LogFile())
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			_, err = conn.Write(payload)
			require.NoError(t, err, "iter %d: write\n%s", i, state.zetClient.LogFile())
			got := make([]byte, len(payload))
			_, err = readFull(conn, got)
			require.NoError(t, err, "iter %d: read echo\n%s", i, state.zetClient.LogFile())
			require.Equal(t, payload, got, "iter %d: TCP echo mismatch", i)
			conn.Close()
		}
	})
}

// TestLeak_TCPLargeTransfer iterates 20 connect/transfer/close cycles, each
// sending 1 MiB over the TCP data path, and asserts no leaks after settle.
// Exercises pbuf pool and TCP PCB lifecycle under sustained data volume.
//
// Requires root/CAP_NET_ADMIN.
func TestLeak_TCPLargeTransfer(t *testing.T) {
	const (
		iterations    = 20
		payloadSize   = 1 << 20 // 1 MiB
		interceptIP   = "100.64.0.21"
		interceptPort = 23001
	)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	interceptZET, hostZET := startLeakZETs(t)
	echo := testutil.StartTCPEcho(t)
	names := t2tNames(t)
	setupT2TService(t, ctx, interceptZET, hostZET, names,
		"tcp", "127.0.0.1", addrPort(t, echo.Addr), interceptIP, interceptPort)

	interceptAddr := net.JoinHostPort(interceptIP, fmt.Sprintf("%d", interceptPort))
	waitCtx, waitCancel := context.WithTimeout(ctx, 30*time.Second)
	defer waitCancel()
	waitForTCPService(t, waitCtx, interceptAddr, interceptZET, hostZET)

	// Fixed-pattern 1 MiB payload: easy to verify and compresses poorly (avoids
	// accidental pass due to compression masking buffer-size bugs).
	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i % 251)
	}

	harness := testutil.NewLeakHarness(t,
		[]*testutil.ZET{interceptZET, hostZET}, tcpLeakPools)

	harness.Run(t, func() {
		for i := range iterations {
			conn, err := net.DialTimeout("tcp", interceptAddr, 10*time.Second)
			require.NoError(t, err, "iter %d: dial\n%s", i, state.zetClient.LogFile())
			_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
			_, err = conn.Write(payload)
			require.NoError(t, err, "iter %d: write 1 MiB\n%s", i, state.zetClient.LogFile())
			got := make([]byte, payloadSize)
			_, err = readFull(conn, got)
			require.NoError(t, err, "iter %d: read 1 MiB\n%s", i, state.zetClient.LogFile())
			require.True(t, bytes.Equal(payload, got), "iter %d: 1 MiB echo mismatch", i)
			conn.Close()
		}
	})
}

// TestLeak_UDPDatagram sends 100 datagrams over a single UDP session and asserts
// no lwIP pool, ziti connection, FD, or RSS leaks after the session closes.
//
// Requires root/CAP_NET_ADMIN.
func TestLeak_UDPDatagram(t *testing.T) {
	const (
		iterations    = 100
		interceptIP   = "100.64.0.22"
		interceptPort = 24000
	)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	interceptZET, hostZET := startLeakZETs(t)
	echo := testutil.StartUDPEcho(t)
	names := t2tNames(t)
	setupT2TService(t, ctx, interceptZET, hostZET, names,
		"udp", "127.0.0.1", addrPort(t, echo.Addr), interceptIP, interceptPort)

	interceptAddr := net.JoinHostPort(interceptIP, fmt.Sprintf("%d", interceptPort))
	waitCtx, waitCancel := context.WithTimeout(ctx, 30*time.Second)
	defer waitCancel()
	waitForUDPService(t, waitCtx, interceptAddr, interceptZET, hostZET)

	harness := testutil.NewLeakHarness(t,
		[]*testutil.ZET{interceptZET, hostZET}, udpLeakPools)
	payload := []byte("hello-ziti-leak-udp")

	harness.Run(t, func() {
		conn, err := net.Dial("udp", interceptAddr)
		require.NoError(t, err, "dial UDP\n%s", state.zetClient.LogFile())
		defer conn.Close()
		for i := range iterations {
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			_, err = conn.Write(payload)
			require.NoError(t, err, "iter %d: write\n%s", i, state.zetClient.LogFile())
			got := make([]byte, len(payload))
			_, err = conn.Read(got)
			require.NoError(t, err, "iter %d: read\n%s", i, state.zetClient.LogFile())
			require.Equal(t, payload, got, "iter %d: UDP echo mismatch", i)
		}
	})
}

// TestLeak_TCPConcurrentFanout opens 20 TCP connections concurrently, each doing
// a single echo exchange, then closes all. Asserts no resource leaks after settle.
// Exercises per-connection state under concurrency.
//
// Requires root/CAP_NET_ADMIN.
func TestLeak_TCPConcurrentFanout(t *testing.T) {
	const (
		concurrency   = 20
		interceptIP   = "100.64.0.23"
		interceptPort = 25000
	)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	interceptZET, hostZET := startLeakZETs(t)
	echo := testutil.StartTCPEcho(t)
	names := t2tNames(t)
	setupT2TService(t, ctx, interceptZET, hostZET, names,
		"tcp", "127.0.0.1", addrPort(t, echo.Addr), interceptIP, interceptPort)

	interceptAddr := net.JoinHostPort(interceptIP, fmt.Sprintf("%d", interceptPort))
	waitCtx, waitCancel := context.WithTimeout(ctx, 30*time.Second)
	defer waitCancel()
	waitForTCPService(t, waitCtx, interceptAddr, interceptZET, hostZET)

	harness := testutil.NewLeakHarness(t,
		[]*testutil.ZET{interceptZET, hostZET}, tcpLeakPools)

	harness.Run(t, func() {
		var wg sync.WaitGroup
		errs := make([]error, concurrency)
		conns := make([]net.Conn, concurrency)

		for i := range concurrency {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				c, err := net.DialTimeout("tcp", interceptAddr, 15*time.Second)
				if err != nil {
					errs[idx] = fmt.Errorf("dial: %w", err)
					return
				}
				conns[idx] = c
				payload := []byte(fmt.Sprintf("fanout-%03d", idx))
				_ = c.SetDeadline(time.Now().Add(15 * time.Second))
				if _, err = c.Write(payload); err != nil {
					errs[idx] = fmt.Errorf("write: %w", err)
					return
				}
				got := make([]byte, len(payload))
				if _, err = readFull(c, got); err != nil {
					errs[idx] = fmt.Errorf("read: %w", err)
					return
				}
				if !bytes.Equal(payload, got) {
					errs[idx] = fmt.Errorf("echo mismatch: sent %q got %q", payload, got)
				}
			}(i)
		}
		wg.Wait()
		for _, c := range conns {
			if c != nil {
				c.Close()
			}
		}
		for i, err := range errs {
			require.NoError(t, err, "goroutine %d\ninterceptZET: %s\nhostZET: %s",
				i, state.zetClient.LogFile(), state.zetHost.LogFile())
		}
	})
}

// addrPort extracts the port number from a "host:port" address string.
func addrPort(t *testing.T, addr string) int {
	t.Helper()
	_, portStr, err := net.SplitHostPort(addr)
	require.NoError(t, err, "parse addr %q", addr)
	var port int
	_, err = fmt.Sscanf(portStr, "%d", &port)
	require.NoError(t, err, "parse port from %q", portStr)
	return port
}
