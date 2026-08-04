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
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openziti/ziti-tunnel-sdk-c/tests/integration/testutil"
	"github.com/stretchr/testify/require"
)

const windowsOldNetFoundry = `Windows.old\Windows\System32\config\systemprofile\AppData\Roaming\NetFoundry`

type upgradeContext struct {
	zet       *testutil.ZET
	configDir string
	backupDir string
}

// newUpgradeContext creates a ZET instance that uses a folder inside dirName
// as its Windows system drive. dirName survives the run for inspection and is
// deleted at the start of the next one.
func newUpgradeContext(t *testing.T, dirName string) *upgradeContext {
	upgradeDir := filepath.Join(state.zetClient.RootDir, dirName)
	require.NoError(t, os.RemoveAll(upgradeDir))
	fakeDrive := filepath.Join(upgradeDir, "fakedrive")

	zet := &testutil.ZET{
		BinPath:       state.zetClient.BinPath,
		Discriminator: "zetUpgrade",
		RootDir:       filepath.Join(upgradeDir, "zet"),
		Verbosity:     state.zetClient.Verbosity,
		Env:           []string{"SystemDrive=" + fakeDrive},
	}
	return &upgradeContext{
		zet:       zet,
		configDir: filepath.Join(zet.RootDir, "identities"),
		backupDir: filepath.Join(fakeDrive, windowsOldNetFoundry),
	}
}

func TestWindowsUpgrade(t *testing.T) {
	t.Run("configSurvivesWindowsUpgrade", configSurvivesWindowsUpgrade)
	t.Run("existingConfigWinsOverBackup", existingConfigWinsOverBackup)
}

func configSurvivesWindowsUpgrade(t *testing.T) {
	testutil.RunWithTimeoutOf(t, time.Second*30, func(t *testing.T) {
		idName := "test_backup_recovery"
		tunIp := "100.200.0.1"
		c := newUpgradeContext(t, "upgrade")
		beforeRecovery := c.runZetBeforeUpgrade(t, idName, tunIp, "trace")

		require.Equal(t, tunIp, beforeRecovery.TunIpv4)
		require.Equal(t, 24, beforeRecovery.TunIpv4Mask)
		require.Equal(t, "trace", beforeRecovery.LogLevel)
		require.True(t, beforeRecovery.AddDns)
		require.Equal(t, 25, beforeRecovery.ApiPageSize)
		require.False(t, beforeRecovery.L2Enabled)
		require.Empty(t, beforeRecovery.PcapInterface)
		require.NotEmpty(t, beforeRecovery.ServiceVersion.Version)

		identityFile := beforeRecovery.Identities[0].Identifier
		enrolledIdentity, err := os.ReadFile(identityFile)
		require.NoError(t, err)

		// The "upgrade": the whole dir moves to Windows.old.
		require.NoError(t, os.MkdirAll(filepath.Dir(c.backupDir), 0o755))
		require.NoError(t, os.Rename(c.configDir, c.backupDir))

		// Second ZET start must restore the backup before the config load.
		require.NoError(t, c.zet.Start())
		afterRecovery := c.zet.WaitForStatusEvent(t)
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
		c.zet.WaitForControllerEvent(t, "connected", idName)

		restoredIdentity, err := os.ReadFile(identityFile)
		require.NoError(t, err)
		require.True(t, bytes.Equal(enrolledIdentity, restoredIdentity), "restored identity file differs from the enrolled one")
		c.assertBackupRemoved(t, idName)
	})
}

func existingConfigWinsOverBackup(t *testing.T) {
	testutil.RunWithTimeoutOf(t, time.Second*30, func(t *testing.T) {
		idName := "test_existing_config_wins_over_backup"
		tunIp := "100.202.0.1"
		c := newUpgradeContext(t, "upgrade-existing-wins")
		existingConfig := c.runZetBeforeUpgrade(t, idName, tunIp, "trace")

		identityFile := existingConfig.Identities[0].Identifier
		existingIdentity, err := os.ReadFile(identityFile)
		require.NoError(t, err)

		// A backup left behind (a failed delete on an earlier boot): its config
		// differs from the existing one and its files are newer on disk.
		require.NoError(t, os.MkdirAll(c.backupDir, 0o755))
		backupConfig := existingConfig
		backupConfig.TunIpv4 = "100.203.0.1"
		backupConfigJSON, err := json.Marshal(backupConfig)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(c.backupDir, "config.json"), backupConfigJSON, 0o644))
		backupIdentity := []byte(`{"marker":"dummy identity"}`)
		require.NoError(t, os.WriteFile(filepath.Join(c.backupDir, idName+".json"), backupIdentity, 0o600))

		// The existing files must win over the newer backup, and the backup is removed.
		require.NoError(t, c.zet.Start())
		afterRecovery := c.zet.WaitForStatusEvent(t)
		require.Equal(t, tunIp, afterRecovery.Status.TunIpv4)

		identityAfterRecovery, err := os.ReadFile(identityFile)
		require.NoError(t, err)
		require.True(t, bytes.Equal(existingIdentity, identityAfterRecovery), "existing identity was overwritten by the backup")
		c.zet.WaitForControllerEvent(t, "connected", idName)

		c.assertBackupRemoved(t, idName)
	})
}

// runZetBeforeUpgrade starts ZET, enrolls idName, updates tunIp and logLevel,
// waits for the config to write to disk, then stops ZET. It returns the saved
// config as a TunnelStatus struct.
func (c *upgradeContext) runZetBeforeUpgrade(t *testing.T, idName, tunIp, logLevel string) testutil.TunnelStatus {
	require.NoError(t, c.zet.Start())
	t.Cleanup(c.zet.Stop)

	testutil.FetchAndEnrollJwt(t, state.overlay, c.zet, idName)
	c.zet.WaitForControllerEvent(t, "connected", idName)

	logLevelResp := c.zet.SetLogLevel(t, logLevel)
	logLevelResp.AssertSuccess()

	interfaceData := testutil.InterfaceConfigData{
		L3: testutil.TunIPv4Data{TunIPv4: tunIp, TunPrefixLength: 24, AddDns: true},
	}
	updateConfigResponse := c.zet.UpdateInterfaceConfig(t, interfaceData)
	updateConfigResponse.AssertSuccess()

	// A command response can arrive before its config save finishes writing, so wait for the settled file
	var savedConfig testutil.TunnelStatus
	configFile := filepath.Join(c.configDir, "config.json")
	deadline := time.Now().Add(2 * time.Second)
	for {
		var tunnelStatus testutil.TunnelStatus
		configJSON, err := os.ReadFile(configFile)
		parsed := err == nil && json.Unmarshal(configJSON, &tunnelStatus) == nil
		if parsed && tunnelStatus.TunIpv4 == tunIp {
			savedConfig = tunnelStatus
			break
		}
		require.False(t, time.Now().After(deadline), "config.json never settled")
		time.Sleep(100 * time.Millisecond)
	}
	c.zet.Stop()

	require.Len(t, savedConfig.Identities, 1)
	return savedConfig
}

func (c *upgradeContext) assertBackupRemoved(t *testing.T, idName string) {
	_, statErr := os.Stat(filepath.Join(c.backupDir, "config.json"))
	require.True(t, os.IsNotExist(statErr), "backup config was not removed")
	_, statErr = os.Stat(filepath.Join(c.backupDir, idName+".json"))
	require.True(t, os.IsNotExist(statErr), "backup identity was not removed")
}
