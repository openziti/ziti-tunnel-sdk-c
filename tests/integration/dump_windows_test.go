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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openziti/ziti-tunnel-sdk-c/tests/integration/testutil"
	"github.com/stretchr/testify/require"
)

func TestDumpFiles(t *testing.T) {
	t.Run("zitiDumpWritesIntoLogDir", zitiDumpWritesIntoLogDir)
	t.Run("ipDumpWritesIntoLogDir", ipDumpWritesIntoLogDir)
}

func zitiDumpWritesIntoLogDir(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		idName := "test_dump_file"
		added := testutil.FetchAndEnrollJwt(t, state.overlay, state.zetClient, idName)

		state.zetClient.WaitForControllerEvent(t, "connected", idName)

		baseName := strings.TrimSuffix(filepath.Base(added.Id.Identifier), ".json")
		dumpFile := filepath.Join(state.zetClient.DumpDir(), baseName+"."+state.zetClient.Discriminator+".ziti")
		t.Cleanup(func() { os.Remove(dumpFile) })

		deadline := time.Now().Add(2 * time.Second)
		dumpResp := state.zetClient.ZitiDump(t, added.Id.Identifier)
		for len(dumpResp.Data.Files) == 0 && time.Now().Before(deadline) {
			time.Sleep(100 * time.Millisecond)
			dumpResp = state.zetClient.ZitiDump(t, added.Id.Identifier)
		}
		dumpResp.AssertSuccess()
		require.Equal(t, []string{dumpFile}, dumpResp.Data.Files)

		fileText, readErr := os.ReadFile(dumpFile)
		require.NoError(t, readErr)
		require.Contains(t, string(fileText), "Config Source:\t"+added.Id.Identifier)
		require.Contains(t, string(fileText), state.overlay.ControllerHostPort())
	})
}

func ipDumpWritesIntoLogDir(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		dumpResp := state.zetClient.IpDump(t)
		dumpResp.AssertSuccess()
		require.Len(t, dumpResp.Data.Files, 1)

		dumpFile := dumpResp.Data.Files[0]
		t.Cleanup(func() { os.Remove(dumpFile) })
		require.Equal(t, state.zetClient.DumpDir(), filepath.Dir(dumpFile))
		require.Contains(t, filepath.Base(dumpFile), "."+state.zetClient.Discriminator+".ip_dump")

		fileText, readErr := os.ReadFile(dumpFile)
		require.NoError(t, readErr)
		require.Contains(t, string(fileText), "Memory Pools:")
	})
}
