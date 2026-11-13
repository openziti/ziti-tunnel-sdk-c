//go:build windows

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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openziti/ziti-tunnel-sdk-c/tests/integration/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestNrptRules(t *testing.T) {
	t.Run("interceptHostnameCannotInjectScript", interceptHostnameCannotInjectScript)
	t.Run("serviceUpdateCannotInjectScript", serviceUpdateCannotInjectScript)
	t.Run("pipeNameCannotInjectScript", pipeNameCannotInjectScript)
}

func interceptHostnameCannotInjectScript(t *testing.T) {
	testutil.RunWithTimeoutOf(t, 20*time.Second, func(t *testing.T) {
		injectedFile := injectedFilePath(t, "zet-injected-by-hostname")
		injectedByCurlyQuoteFile := injectedFilePath(t, "zet-injected-by-curly-quote-hostname")

		event := testutil.FetchAndEnrollJwt(t, state.overlay, state.zetClient, "test_nrpt_hostname")
		requireNrptRule(t, state.zetClient, "safe.nrpt-test.ziti", 5*time.Second)
		requireNrptRule(t, state.zetClient, "münchen.nrpt-test.ziti", 5*time.Second)

		state.zetClient.RemoveIdentity(t, event.Id.Identifier).AssertSuccess()
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			namespaces, err := nrptNamespaces(state.zetClient)
			assert.NoError(c, err)
			assert.NotContains(c, namespaces, "safe.nrpt-test.ziti")
		}, 5*time.Second, 500*time.Millisecond, "removing the identity left the NRPT rule for safe.nrpt-test.ziti")

		require.NoFileExists(t, injectedFile, "intercept hostname allowed an injected command to run")
		require.NoFileExists(t, injectedByCurlyQuoteFile, "curly quote intercept hostname allowed an injected command to run")
	})
}

func serviceUpdateCannotInjectScript(t *testing.T) {
	testutil.RunWithTimeoutOf(t, 45*time.Second, func(t *testing.T) {
		injectedFile := injectedFilePath(t, "zet-injected-by-service-update")

		testutil.FetchAndEnrollJwt(t, state.overlay, state.zetClient, "test_nrpt_update")
		requireNrptRule(t, state.zetClient, "safe.nrpt-update-test.ziti", 5*time.Second)

		require.NoError(t, state.overlay.UpdateInterceptConfigV1("test_nrpt_update_intercept", []string{"tcp"},
			[]string{
				"safe.nrpt-update-test.ziti",
				"added.nrpt-update-test.ziti",
				"x';m=(New-Item -ItemType File -Path $env:PUBLIC -Name 'zet-injected-by-service-update');x='",
			}, 80, 80))
		requireNrptRule(t, state.zetClient, "added.nrpt-update-test.ziti", 30*time.Second)

		require.NoFileExists(t, injectedFile, "service update allowed an injected command to run")
	})
}

func pipeNameCannotInjectScript(t *testing.T) {
	requireMultiTunnel(t)
	testutil.RunWithTimeoutOf(t, 30*time.Second, func(t *testing.T) {
		injectedFile := injectedFilePath(t, "zet-injected-by-pipe-name")

		testutil.FetchAndEnrollJwt(t, state.overlay, state.zetHost, "test_nrpt_zetb")
		requireNrptRule(t, state.zetHost, "zetb.nrpt-test.ziti", 5*time.Second)

		// names the folder through $env:PUBLIC because a pipe name cannot hold a backslash
		pipePath := testutil.CommandPipePathFor("x');New-Item -ItemType File -Path $env:PUBLIC -Name 'zet-injected-by-pipe-name';$x=('")
		pipeName, err := windows.UTF16PtrFromString(pipePath)
		require.NoError(t, err)
		pipe, err := windows.CreateNamedPipe(pipeName, windows.PIPE_ACCESS_DUPLEX, windows.PIPE_TYPE_BYTE, 1, 0, 0, 0, nil)
		require.NoError(t, err)
		t.Cleanup(func() { _ = windows.CloseHandle(pipe) })

		require.NoError(t, state.zetClient.Restart(), "restart %s\n%s", state.zetClient.Discriminator,
			state.zetClient.LogPath())

		require.NoFileExists(t, injectedFile, "pipe name allowed an injected command to run")
		namespaces, err := nrptNamespaces(state.zetHost)
		require.NoError(t, err)
		require.Contains(t, namespaces, "zetb.nrpt-test.ziti", "restarting %s removed the NRPT rule of running %s",
			state.zetClient.Discriminator, state.zetHost.Discriminator)
	})
}

func requireNrptRule(t *testing.T, zet *testutil.ZET, namespace string, timeout time.Duration) {
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		namespaces, err := nrptNamespaces(zet)
		assert.NoError(c, err)
		assert.Contains(c, namespaces, namespace)
	}, timeout, 500*time.Millisecond, "%s added no NRPT rule for %s", zet.Discriminator, namespace)
}

func injectedFilePath(t *testing.T, name string) string {
	injectedFile := filepath.Join(os.Getenv("PUBLIC"), name)
	require.NoError(t, os.RemoveAll(injectedFile))
	t.Cleanup(func() { _ = os.Remove(injectedFile) })
	return injectedFile
}

func nrptNamespaces(zet *testutil.ZET) ([]string, error) {
	comment := "Added by " + zet.Discriminator + ".ziti-edge-tunnel"
	script := "[Console]::OutputEncoding = [Text.Encoding]::UTF8; " +
		"Get-DnsClientNrptRule | Where-Object Comment -eq '" + comment + "' | ForEach-Object { $_.Namespace }"
	out, err := exec.Command("powershell", "-NoProfile", "-Command", script).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("list NRPT rules: %w\n%s", err, out)
	}
	return strings.Fields(string(out)), nil
}
