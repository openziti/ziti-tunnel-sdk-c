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
		logLevel := "debug"

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

		// First ZET start writes a config: enrolled identity + range and log level changed
		testutil.FetchAndEnrollJwt(t, state.overlay, zet, idName)
		zet.WaitForControllerEvent(t, "connected", idName)
		interfaceData := testutil.InterfaceConfigData{
			L3: testutil.TunIPv4Data{TunIPv4: tunIp, TunPrefixLength: 24, AddDns: true},
		}

		updateConfigResponse := zet.UpdateInterfaceConfig(t, interfaceData)
		updateConfigResponse.AssertSuccess()

		logLevelResp := zet.SetLogLevel(t, logLevel)
		logLevelResp.AssertSuccess()

		// A command response can arrive before its config save finishes writing, so wait for the settled file
		var beforeRecovery testutil.TunnelStatus
		configFile := filepath.Join(configDir, "config.json")
		deadline := time.Now().Add(5 * time.Second)
		for {
			configJSON, err := os.ReadFile(configFile)
			parsed := err == nil && json.Unmarshal(configJSON, &beforeRecovery) == nil
			if parsed && beforeRecovery.LogLevel == logLevel {
				break
			}
			require.False(t, time.Now().After(deadline), "config.json never settled")
			time.Sleep(100 * time.Millisecond)
		}
		zet.Stop()

		require.Equal(t, tunIp, beforeRecovery.TunIpv4)
		require.Equal(t, 24, beforeRecovery.TunIpv4Mask)
		require.True(t, beforeRecovery.AddDns)
		require.Equal(t, 25, beforeRecovery.ApiPageSize)
		require.False(t, beforeRecovery.L2Enabled)
		require.Empty(t, beforeRecovery.PcapInterface)
		require.NotEmpty(t, beforeRecovery.ServiceVersion.Version)
		require.Len(t, beforeRecovery.Identities, 1)

		identityFile := beforeRecovery.Identities[0].Identifier
		enrolledIdentity, err := os.ReadFile(identityFile)
		require.NoError(t, err)

		// The "upgrade": the whole dir moves to Windows.old.
		backupDir := filepath.Join(fakeDrive, `Windows.old\Windows\System32\config\systemprofile\AppData\Roaming\NetFoundry`)
		require.NoError(t, os.MkdirAll(filepath.Dir(backupDir), 0o755))
		require.NoError(t, os.Rename(configDir, backupDir))

		// Second ZET start must restore the backup before the config load.
		require.NoError(t, zet.Start())
		afterRecovery := zet.WaitForStatusEvent(t)
		require.Equal(t, beforeRecovery.TunIpv4, afterRecovery.Status.TunIpv4)
		require.Equal(t, afterRecovery.Status.TunIpv4, afterRecovery.Status.IpInfo.Ip)
		require.Equal(t, beforeRecovery.TunIpv4Mask, afterRecovery.Status.TunIpv4Mask)
		require.Equal(t, beforeRecovery.LogLevel, afterRecovery.Status.LogLevel)
		require.Equal(t, beforeRecovery.AddDns, afterRecovery.Status.AddDns)
		require.Equal(t, beforeRecovery.ApiPageSize, afterRecovery.Status.ApiPageSize)
		require.Equal(t, beforeRecovery.L2Enabled, afterRecovery.Status.L2Enabled)
		require.Equal(t, beforeRecovery.PcapInterface, afterRecovery.Status.PcapInterface)
		require.Equal(t, beforeRecovery.ServiceVersion, afterRecovery.Status.ServiceVersion)

		restored := findIdentityInStatus(t, afterRecovery, identityFile)
		assertValidJwtIdState(t, restored)
		zet.WaitForControllerEvent(t, "connected", idName)

		restoredIdentity, err := os.ReadFile(identityFile)
		require.NoError(t, err)
		require.Equal(t, enrolledIdentity, restoredIdentity, "restored identity file differs from the enrolled one")
		_, statErr := os.Stat(filepath.Join(backupDir, "config.json"))
		require.True(t, os.IsNotExist(statErr), "backup config was not removed")
		_, statErr = os.Stat(filepath.Join(backupDir, idName+".json"))
		require.True(t, os.IsNotExist(statErr), "backup identity was not removed")
	})
}
