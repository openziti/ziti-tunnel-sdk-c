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
	"testing"
	"time"

	"github.com/openziti/ziti-tunnel-sdk-c/tests/integration/testutil"
	"github.com/stretchr/testify/require"
)

func TestDump(t *testing.T) {
	t.Run("zitiDumpReturnsIdentityDump", zitiDumpReturnsIdentityDump)
	t.Run("zitiDumpRejectsUnknownIdentifier", zitiDumpRejectsUnknownIdentifier)
	t.Run("zitiDumpReturnsAllIdentities", zitiDumpReturnsAllIdentities)
	t.Run("zitiDumpIgnoresDumpPath", zitiDumpIgnoresDumpPath)
	t.Run("ipDumpReturnsStats", ipDumpReturnsStats)
	t.Run("ipDumpIgnoresDumpPath", ipDumpIgnoresDumpPath)
}

func zitiDumpReturnsIdentityDump(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		idName := "test_dump"
		added := testutil.FetchAndEnrollJwt(t, state.overlay, state.zetClient, idName)

		state.zetClient.WaitForControllerEvent(t, "connected", idName)

		// ziti_get_identity is NULL until login completes, so a dump sent in that window skips the identity
		// and still reports success
		deadline := time.Now().Add(2 * time.Second)
		dumpResp := state.zetClient.ZitiDump(t, added.Id.Identifier)
		for len(dumpResp.Data.Dumps) == 0 && time.Now().Before(deadline) {
			time.Sleep(100 * time.Millisecond)
			dumpResp = state.zetClient.ZitiDump(t, added.Id.Identifier)
		}
		dumpResp.AssertSuccess()
		require.Len(t, dumpResp.Data.Dumps, 1)
		require.Contains(t, dumpResp.Data.Dumps, added.Id.Identifier)

		dumpText := dumpResp.Data.Dumps[added.Id.Identifier]
		require.Contains(t, dumpText, "Config Source:\t"+added.Id.Identifier)
		require.Contains(t, dumpText, state.overlay.ControllerHostPort())
		require.Contains(t, dumpText, "auth_state[FullyAuthenticated]")
	})
}

func zitiDumpRejectsUnknownIdentifier(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		dumpResp := state.zetClient.ZitiDump(t, "no-such-identity")
		dumpResp.AssertFail(500, "No matching identifier found")
	})
}

func zitiDumpReturnsAllIdentities(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		firstName := "test_dump_all_first"
		secondName := "test_dump_all_second"
		first := testutil.FetchAndEnrollJwt(t, state.overlay, state.zetClient, firstName)
		state.zetClient.WaitForControllerEvent(t, "connected", firstName)
		second := testutil.FetchAndEnrollJwt(t, state.overlay, state.zetClient, secondName)
		state.zetClient.WaitForControllerEvent(t, "connected", secondName)

		deadline := time.Now().Add(2 * time.Second)
		dumpResp := state.zetClient.ZitiDump(t, "")
		for time.Now().Before(deadline) {
			_, firstDumped := dumpResp.Data.Dumps[first.Id.Identifier]
			_, secondDumped := dumpResp.Data.Dumps[second.Id.Identifier]
			if firstDumped && secondDumped {
				break
			}
			time.Sleep(100 * time.Millisecond)
			dumpResp = state.zetClient.ZitiDump(t, "")
		}
		dumpResp.AssertSuccess()
		require.Contains(t, dumpResp.Data.Dumps, first.Id.Identifier)
		require.Contains(t, dumpResp.Data.Dumps, second.Id.Identifier)
		require.Contains(t, dumpResp.Data.Dumps[first.Id.Identifier], "Config Source:\t"+first.Id.Identifier)
		require.Contains(t, dumpResp.Data.Dumps[second.Id.Identifier], "Config Source:\t"+second.Id.Identifier)
	})
}

func zitiDumpIgnoresDumpPath(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		idName := "test_dump_path"
		added := testutil.FetchAndEnrollJwt(t, state.overlay, state.zetClient, idName)
		state.zetClient.WaitForControllerEvent(t, "connected", idName)

		callerDir := t.TempDir()
		deadline := time.Now().Add(2 * time.Second)
		dumpResp := state.zetClient.ZitiDumpWithDumpPath(t, added.Id.Identifier, callerDir)
		for len(dumpResp.Data.Dumps) == 0 && time.Now().Before(deadline) {
			time.Sleep(100 * time.Millisecond)
			dumpResp = state.zetClient.ZitiDumpWithDumpPath(t, added.Id.Identifier, callerDir)
		}
		dumpResp.AssertSuccess()
		require.Contains(t, dumpResp.Data.Dumps, added.Id.Identifier)
		leftBehind, readErr := os.ReadDir(callerDir)
		require.NoError(t, readErr)
		require.Empty(t, leftBehind)
	})
}

func ipDumpReturnsStats(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		dumpResp := state.zetClient.IpDump(t)
		dumpResp.AssertSuccess()
		require.NotEmpty(t, dumpResp.Data.Stats.Pools)
	})
}

func ipDumpIgnoresDumpPath(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		callerDir := t.TempDir()
		dumpResp := state.zetClient.IpDumpWithDumpPath(t, callerDir)
		dumpResp.AssertSuccess()
		require.NotEmpty(t, dumpResp.Data.Stats.Pools)
		leftBehind, readErr := os.ReadDir(callerDir)
		require.NoError(t, readErr)
		require.Empty(t, leftBehind)
	})
}
