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
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openziti/ziti-tunnel-sdk-c/tests/integration/testutil"
	"github.com/stretchr/testify/require"
)

func TestWindowsUpgrade(t *testing.T) {
	t.Run("configSurvivesWindowsUpgrade", configSurvivesWindowsUpgrade)
}

func configSurvivesWindowsUpgrade(t *testing.T) {
	testutil.RunWithTimeoutOf(t, time.Second*30, func(t *testing.T) {
		fakeDrive := filepath.Join(t.TempDir(), "fakedrive")
		idName := "test_backup_recovery"
		tunIp := "100.200.0.1"

		zet := &testutil.ZET{
			BinPath:       state.zetClient.BinPath,
			Discriminator: "zetUpgrade",
			RootDir:       filepath.Join(t.TempDir(), "zet"),
			Verbosity:     state.zetClient.Verbosity,
			Env:           []string{"SystemDrive=" + fakeDrive},
		}
		configDir := filepath.Join(zet.RootDir, "identities")
		require.NoError(t, zet.Start())
		t.Cleanup(zet.Stop)

		// First run writes a config: enrolled identity + range and log level changed
		testutil.FetchAndEnrollJwt(t, state.overlay, zet, idName)
		zet.WaitForControllerEvent(t, "connected", idName)
		interfaceData := testutil.InterfaceConfigData{
			L3: testutil.TunIPv4Data{TunIPv4: tunIp, TunPrefixLength: 24, AddDns: true},
		}

		updateConfigResponse := zet.UpdateInterfaceConfig(t, interfaceData)
		updateConfigResponse.AssertSuccess()

		logLevelResp := zet.SetLogLevel(t, "debug")
		logLevelResp.AssertSuccess()

		// A single read can catch a stale or torn file.
		// Poll until the settled config is on disk, then it is safe to kill.
		configFile := filepath.Join(configDir, "config.json")
		baseline := waitForSavedConfig(t, configFile, tunIp, "debug")
		zet.Stop()

		identityFile := baseline.Identities[0].Identifier
		enrolledIdentity, err := os.ReadFile(identityFile)
		require.NoError(t, err)

		// The upgrade: the whole dir moves to Windows.old.
		backupDir := filepath.Join(fakeDrive, `Windows.old\Windows\System32\config\systemprofile\AppData\Roaming\NetFoundry`)
		require.NoError(t, os.MkdirAll(filepath.Dir(backupDir), 0o755))
		require.NoError(t, os.Rename(configDir, backupDir))

		// Second run must restore the backup before the config load.
		require.NoError(t, zet.Start())
		status := zet.WaitForStatusEvent(t)
		require.Equal(t, baseline.TunIpv4, status.Status.TunIpv4)
		require.Equal(t, baseline.TunIpv4Mask, status.Status.TunIpv4Mask)
		require.Equal(t, baseline.LogLevel, status.Status.LogLevel)
		restored := findIdentityInStatus(t, status, identityFile)
		assertValidJwtIdState(t, restored)
		zet.WaitForControllerEvent(t, "connected", idName)

		restoredIdentity, err := os.ReadFile(identityFile)
		require.NoError(t, err)
		require.Equal(t, enrolledIdentity, restoredIdentity, "restored identity file differs from the enrolled one")
		_, statErr := os.Stat(filepath.Join(backupDir, "config.json"))
		require.True(t, os.IsNotExist(statErr), "backup config.json was not consumed")
		_, statErr = os.Stat(filepath.Join(backupDir, idName+".json"))
		require.True(t, os.IsNotExist(statErr), "backup identity file was not consumed")
	})
}

func waitForSavedConfig(t *testing.T, configFile string, tunIp string, logLevel string) testutil.TunnelStatus {
	deadline := time.Now().Add(10 * time.Second)
	var tunnelStatus testutil.TunnelStatus
	for {
		configJSON, readErr := os.ReadFile(configFile)
		if readErr == nil && json.Unmarshal(configJSON, &tunnelStatus) == nil {
			settled := tunnelStatus.TunIpv4 == tunIp &&
				strings.EqualFold(tunnelStatus.LogLevel, logLevel) && len(tunnelStatus.Identities) == 1
			if settled {
				return tunnelStatus
			}
		}
		if time.Now().After(deadline) {
			require.FailNow(t, "config.json never contained the configured range, log level and identity", "file=%s status=%+v", configFile, tunnelStatus)
		}
		time.Sleep(250 * time.Millisecond)
	}
}
