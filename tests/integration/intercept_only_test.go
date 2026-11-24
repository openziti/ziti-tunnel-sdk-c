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
	"testing"
	"time"

	"github.com/openziti/ziti-tunnel-sdk-c/tests/integration/testutil"
	"github.com/stretchr/testify/require"
)

// TestInterceptOnly switches the hosting ZET to intercept-only and back over IPC, and checks how the mode is saved
// and held by -O. The restarts run on zetB, which hosts; zetA keeps intercepting.
//
// Requires root/CAP_NET_ADMIN — both ZETs open TUN devices.
func TestInterceptOnly(t *testing.T) {
	requireMultiTunnel(t)
	t.Run("switchStopsAndResumesHosting", switchStopsAndResumesHosting)
	t.Run("rejectsMalformedPayload", rejectsMalformedInterceptOnly)
	t.Run("savedAcrossRestart", interceptOnlySavedAcrossRestart)
	t.Run("flagHoldsItForTheRun", interceptOnlyFlagHoldsItForTheRun)
}

func switchStopsAndResumesHosting(t *testing.T) {
	testutil.RunWithTimeoutOf(t, 120*time.Second, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 110*time.Second)
		defer cancel()
		interceptZET, hostZET := state.zetClient, state.zetHost
		t.Cleanup(func() { hostZET.SetInterceptOnly(t, false).AssertSuccess() })

		echo := testutil.StartTCPEcho(t, "127.0.0.1:0")
		_, echoPort, err := net.SplitHostPort(echo.Addr)
		require.NoError(t, err, "parse echo addr")
		echoPortInt := 0
		fmt.Sscanf(echoPort, "%d", &echoPortInt)

		const interceptIP, interceptPort = "100.64.0.12", 21003
		setupT2TService(t, ctx, interceptZET, hostZET, t2tNames(t), "tcp", "127.0.0.1", echoPortInt,
			interceptIP+"/32", interceptPort)
		addr := net.JoinHostPort(interceptIP, fmt.Sprintf("%d", interceptPort))
		waitForTCPService(t, ctx, addr, interceptZET, hostZET)

		hostZET.SkipToNow()
		hostZET.SetInterceptOnly(t, true).AssertSuccess()
		require.True(t, hostZET.WaitForStatusEvent(t).Status.InterceptOnly, "status event after switching on")
		require.True(t, hostZET.Status(t).Data.InterceptOnly, "status after switching on")
		// saved before the reply
		require.Equal(t, true, hostZET.ReadTunnelConfig(t)["InterceptOnly"], "config.json after switching on")
		require.Eventually(t, func() bool { return !echoes(addr) }, 30*time.Second, 500*time.Millisecond,
			"still hosted after switching on\nhostZET: %s", hostZET.LogFile())

		hostZET.SetInterceptOnly(t, true).AssertSuccess() // again: nothing changes

		hostZET.SkipToNow()
		hostZET.SetInterceptOnly(t, false).AssertSuccess()
		require.False(t, hostZET.WaitForStatusEvent(t).Status.InterceptOnly, "status event after switching off")
		require.False(t, hostZET.Status(t).Data.InterceptOnly, "status after switching off")
		require.Equal(t, false, hostZET.ReadTunnelConfig(t)["InterceptOnly"], "config.json after switching off")
		require.Eventually(t, func() bool { return echoes(addr) }, 30*time.Second, 500*time.Millisecond,
			"not hosted again after switching off\ninterceptZET: %s\nhostZET: %s", interceptZET.LogFile(), hostZET.LogFile())
	})
}

// a missing value must not read as false, which would turn the mode off
func rejectsMalformedInterceptOnly(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		hostZET := state.zetHost
		t.Cleanup(func() { hostZET.SetInterceptOnly(t, false).AssertSuccess() })
		hostZET.SetInterceptOnly(t, true).AssertSuccess()

		for _, data := range []any{
			map[string]any{},
			map[string]any{"InterceptOnly": nil},
			map[string]any{"InterceptOnly": "false"},
			map[string]any{"InterceptOnly": 0},
			nil,
		} {
			hostZET.SendSetInterceptOnly(t, data).AssertFail(500, "invalid command")
		}
		require.True(t, hostZET.Status(t).Data.InterceptOnly, "a malformed command changed the mode")
	})
}

func interceptOnlySavedAcrossRestart(t *testing.T) {
	testutil.RunWithTimeoutOf(t, 60*time.Second, func(t *testing.T) {
		hostZET := state.zetHost
		t.Cleanup(func() { hostZET.SetInterceptOnly(t, false).AssertSuccess() })

		hostZET.SetInterceptOnly(t, true).AssertSuccess()
		require.NoError(t, hostZET.Restart(), "restart\n%s", hostZET.LogFile())
		require.True(t, hostZET.Status(t).Data.InterceptOnly, "a saved on applies after a restart")

		hostZET.SetInterceptOnly(t, false).AssertSuccess()
		require.NoError(t, hostZET.Restart(), "restart\n%s", hostZET.LogFile())
		require.False(t, hostZET.Status(t).Data.InterceptOnly, "a saved off applies after a restart")
	})
}

// -O holds intercept-only for the run without saving it, so removing it brings back the saved choice
func interceptOnlyFlagHoldsItForTheRun(t *testing.T) {
	testutil.RunWithTimeoutOf(t, 90*time.Second, func(t *testing.T) {
		hostZET := state.zetHost
		args := hostZET.ExtraArgs
		t.Cleanup(func() {
			if len(hostZET.ExtraArgs) != len(args) {
				hostZET.ExtraArgs = args
				require.NoError(t, hostZET.Restart(), "restart without -O\n%s", hostZET.LogFile())
			}
			hostZET.SetInterceptOnly(t, false).AssertSuccess()
		})

		hostZET.ExtraArgs = append(append([]string{}, args...), "-O")
		require.NoError(t, hostZET.Restart(), "restart with -O\n%s", hostZET.LogFile())
		require.True(t, hostZET.Status(t).Data.InterceptOnly, "-O")
		require.Equal(t, false, hostZET.ReadTunnelConfig(t)["InterceptOnly"], "-O is saved")

		hostZET.SetInterceptOnly(t, false).AssertFail(500, "set by -O")
		require.True(t, hostZET.Status(t).Data.InterceptOnly, "a refused off changed the mode")

		hostZET.SetInterceptOnly(t, true).AssertSuccess() // on is allowed, and saved
		require.Equal(t, true, hostZET.ReadTunnelConfig(t)["InterceptOnly"], "on under -O is not saved")

		hostZET.ExtraArgs = args
		require.NoError(t, hostZET.Restart(), "restart without -O\n%s", hostZET.LogFile())
		require.True(t, hostZET.Status(t).Data.InterceptOnly, "the saved on applies without -O")
		hostZET.SetInterceptOnly(t, false).AssertSuccess()
		require.False(t, hostZET.Status(t).Data.InterceptOnly, "off without -O")
	})
}

// echoes reports whether a round trip through addr comes back, so the service is hosted end to end
func echoes(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	payload := []byte("intercept-only")
	if _, err = conn.Write(payload); err != nil {
		return false
	}
	got := make([]byte, len(payload))
	_, err = readFull(conn, got)
	return err == nil && bytes.Equal(got, payload)
}
