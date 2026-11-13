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
	"os"
	"strings"
	"testing"
	"time"

	"github.com/openziti/ziti-tunnel-sdk-c/tests/integration/testutil"
	"github.com/stretchr/testify/require"
)

const proxyWithLogin = "http://user:secret@proxy.invalid:3128"

func TestSetProxy(t *testing.T) {
	t.Run("savesProxyInConfig", savesProxyInConfig)
	t.Run("overwritesSavedProxy", overwritesSavedProxy)
	t.Run("emptyProxyRemovesSavedProxy", emptyProxyRemovesSavedProxy)
	t.Run("emptyProxySucceedsWithNoSavedProxy", emptyProxySucceedsWithNoSavedProxy)
	t.Run("rejectsNonHttpProxy", rejectsNonHttpProxy)
	t.Run("rejectsProxyWithoutPort", rejectsProxyWithoutPort)
	t.Run("rejectsProxyWithoutHostname", rejectsProxyWithoutHostname)
	t.Run("rejectedProxyKeepsSavedProxy", rejectedProxyKeepsSavedProxy)
	t.Run("restartUsesSavedProxy", restartUsesSavedProxy)
	t.Run("savedProxyPasswordStaysOutOfStatus", savedProxyPasswordStaysOutOfStatus)
}

func waitForSavedProxy(t *testing.T, proxy string) {
	require.Eventually(t, func() bool {
		return state.zetClient.ReadTunnelConfig(t)["Proxy"] == proxy
	}, 2*time.Second, 100*time.Millisecond)
}

func clearSavedProxy(t *testing.T) {
	clearResp := state.zetClient.SetProxy(t, "")
	clearResp.AssertSuccess()
	require.Eventually(t, func() bool {
		_, saved := state.zetClient.ReadTunnelConfig(t)["Proxy"]
		return !saved
	}, 2*time.Second, 100*time.Millisecond)
}

func savesProxyInConfig(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		t.Cleanup(func() { clearSavedProxy(t) })

		setProxyResp := state.zetClient.SetProxy(t, proxyWithLogin)
		setProxyResp.AssertSuccess()

		waitForSavedProxy(t, proxyWithLogin)
	})
}

func overwritesSavedProxy(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		t.Cleanup(func() { clearSavedProxy(t) })

		firstResp := state.zetClient.SetProxy(t, proxyWithLogin)
		firstResp.AssertSuccess()
		waitForSavedProxy(t, proxyWithLogin)
		replacementProxy := "http://proxy.invalid:8080"
		replaceResp := state.zetClient.SetProxy(t, replacementProxy)
		replaceResp.AssertSuccess()

		waitForSavedProxy(t, replacementProxy)
	})
}

func emptyProxyRemovesSavedProxy(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		setProxyResp := state.zetClient.SetProxy(t, proxyWithLogin)
		setProxyResp.AssertSuccess()
		waitForSavedProxy(t, proxyWithLogin)

		clearSavedProxy(t)
	})
}

func emptyProxySucceedsWithNoSavedProxy(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		clearSavedProxy(t)

		emptyResp := state.zetClient.SetProxy(t, "")
		emptyResp.AssertSuccess()

		_, saved := state.zetClient.ReadTunnelConfig(t)["Proxy"]
		require.False(t, saved)
	})
}

func rejectsNonHttpProxy(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		setProxyResp := state.zetClient.SetProxy(t, "socks5://proxy.invalid:1080")
		setProxyResp.AssertFail(500, "'http' is the only supported type")
	})
}

func rejectsProxyWithoutPort(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		setProxyResp := state.zetClient.SetProxy(t, "http://proxy.invalid")
		setProxyResp.AssertFail(500, "proxy url has no port")
	})
}

func rejectsProxyWithoutHostname(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		setProxyResp := state.zetClient.SetProxy(t, "http://")
		setProxyResp.AssertFail(500, "proxy url has no hostname")
	})
}

func rejectedProxyKeepsSavedProxy(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		t.Cleanup(func() { clearSavedProxy(t) })

		setProxyResp := state.zetClient.SetProxy(t, proxyWithLogin)
		setProxyResp.AssertSuccess()
		waitForSavedProxy(t, proxyWithLogin)
		rejectedResp := state.zetClient.SetProxy(t, "http://proxy.invalid")
		rejectedResp.AssertFail(500, "proxy url has no port")

		require.Never(t, func() bool {
			return state.zetClient.ReadTunnelConfig(t)["Proxy"] != proxyWithLogin
		}, 1*time.Second, 100*time.Millisecond)
	})
}

func restartUsesSavedProxy(t *testing.T) {
	testutil.RunWithTimeoutOf(t, restartTestTimeout, func(t *testing.T) {
		t.Cleanup(func() {
			clearSavedProxy(t)
			require.NoError(t, state.zetClient.Restart(), "restart %s\n%s", state.zetClient.Discriminator, state.zetClient.LogPath())
		})

		setProxyResp := state.zetClient.SetProxy(t, proxyWithLogin)
		setProxyResp.AssertSuccess()
		waitForSavedProxy(t, proxyWithLogin)

		logBeforeRestart, err := os.ReadFile(state.zetClient.LogFile())
		require.NoError(t, err)
		require.NoError(t, state.zetClient.Restart(), "restart %s\n%s", state.zetClient.Discriminator, state.zetClient.LogPath())

		require.Eventually(t, func() bool {
			logAfterRestart, err := os.ReadFile(state.zetClient.LogFile())
			require.NoError(t, err)
			return strings.Contains(string(logAfterRestart[len(logBeforeRestart):]), "through proxy 'proxy.invalid:3128'")
		}, 2*time.Second, 100*time.Millisecond, "no proxy line after restart in %s", state.zetClient.LogFile())
	})
}

func savedProxyPasswordStaysOutOfStatus(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		t.Cleanup(func() { clearSavedProxy(t) })

		setProxyResp := state.zetClient.SetProxy(t, proxyWithLogin)
		setProxyResp.AssertSuccess()
		waitForSavedProxy(t, proxyWithLogin)

		statusJSON := state.zetClient.StatusJSON(t)
		require.NotContains(t, string(statusJSON), "secret")
	})
}
