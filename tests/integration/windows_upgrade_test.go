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

type upgradeContext struct {
	zet       *testutil.ZET
	idName    string
	configDir string
	backupDir string
	tunIp     string
}

// newUpgradeContext creates a ZET instance that uses a folder inside dirName
// as its Windows system drive. dirName survives the run for inspection and is
// deleted at the start of the next one.
func newUpgradeContext(t *testing.T, dirName, idName string) *upgradeContext {
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
		idName:    idName,
		configDir: filepath.Join(zet.RootDir, "identities"),
		backupDir: filepath.Join(fakeDrive, `Windows.old\Windows\System32\config\systemprofile\AppData\Roaming\NetFoundry`),
		tunIp:     "100.200.0.1",
	}
}

func TestWindowsUpgrade(t *testing.T) {
	t.Run("configSurvivesWindowsUpgrade", configSurvivesWindowsUpgrade)
	t.Run("existingConfigWinsOverBackup", existingConfigWinsOverBackup)
	t.Run("restoreOnlyCopiesMissingFiles", restoreOnlyCopiesMissingFiles)
}

func configSurvivesWindowsUpgrade(t *testing.T) {
	testutil.RunWithTimeoutOf(t, time.Second*30, func(t *testing.T) {
		c := newUpgradeContext(t, "upgrade", "test_config_survives_windows_upgrade")
		beforeRecovery := c.runZetBeforeUpgrade(t)

		require.Equal(t, c.tunIp, beforeRecovery.TunIpv4)
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
		c.zet.WaitForControllerEvent(t, "connected", c.idName)

		assertIdentityUnchanged(t, identityFile, enrolledIdentity)

		// Ensure backup files were deleted
		_, statErr := os.Stat(filepath.Join(c.backupDir, "config.json"))
		require.True(t, os.IsNotExist(statErr), "backup config was not removed")
		_, statErr = os.Stat(filepath.Join(c.backupDir, c.idName+".json"))
		require.True(t, os.IsNotExist(statErr), "backup identity was not removed")
	})
}

func existingConfigWinsOverBackup(t *testing.T) {
	testutil.RunWithTimeoutOf(t, time.Second*30, func(t *testing.T) {
		c := newUpgradeContext(t, "upgrade-existing-wins", "test_existing_config_wins_over_backup")
		beforeRecovery := c.runZetBeforeUpgrade(t)

		identityFile := beforeRecovery.Identities[0].Identifier
		enrolledIdentity, err := os.ReadFile(identityFile)
		require.NoError(t, err)

		// A backup left behind like a failed delete on an earlier boot: its config
		// differs from the existing one and its files are newer on disk.
		require.NoError(t, os.MkdirAll(c.backupDir, 0o755))
		backupConfig := beforeRecovery
		backupConfig.TunIpv4 = "100.203.0.1"
		backupConfigJSON, err := json.Marshal(backupConfig)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(c.backupDir, "config.json"), backupConfigJSON, 0o644))
		backupIdentity := []byte(`{"marker":"dummy identity"}`)
		require.NoError(t, os.WriteFile(filepath.Join(c.backupDir, c.idName+".json"), backupIdentity, 0o600))

		// The existing files must win over the newer backup, and the backup is left in place.
		require.NoError(t, c.zet.Start())
		afterRecovery := c.zet.WaitForStatusEvent(t)
		require.Equal(t, c.tunIp, afterRecovery.Status.TunIpv4)

		assertIdentityUnchanged(t, identityFile, enrolledIdentity)
		c.zet.WaitForControllerEvent(t, "connected", c.idName)

		// Ensure backup files were not deleted
		_, statErr := os.Stat(filepath.Join(c.backupDir, "config.json"))
		require.NoError(t, statErr)
		_, statErr = os.Stat(filepath.Join(c.backupDir, c.idName+".json"))
		require.NoError(t, statErr)
	})
}

func restoreOnlyCopiesMissingFiles(t *testing.T) {
	testutil.RunWithTimeoutOf(t, time.Second*30, func(t *testing.T) {
		c := newUpgradeContext(t, "upgrade-partial-restore", "test_restore_only_copies_missing_files")
		beforeRecovery := c.runZetBeforeUpgrade(t)

		identityFile := beforeRecovery.Identities[0].Identifier
		enrolledIdentity, err := os.ReadFile(identityFile)
		require.NoError(t, err)

		// An earlier boot restored config.json but failed to delete it from the backup, and the identity copy failed.
		require.NoError(t, os.MkdirAll(c.backupDir, 0o755))
		require.NoError(t, os.Rename(identityFile, filepath.Join(c.backupDir, c.idName+".json")))
		configJSON, err := os.ReadFile(filepath.Join(c.configDir, "config.json"))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(c.backupDir, "config.json"), configJSON, 0o644))

		require.NoError(t, c.zet.Start())
		afterRecovery := c.zet.WaitForStatusEvent(t)
		require.Equal(t, c.tunIp, afterRecovery.Status.TunIpv4)

		restored := findIdentityInStatus(t, afterRecovery, identityFile)
		assertValidJwtIdState(t, restored)
		c.zet.WaitForControllerEvent(t, "connected", c.idName)

		assertIdentityUnchanged(t, identityFile, enrolledIdentity)

		// The missing identity was restored and deleted from the backup, the existing config should still be in the backup folder.
		_, statErr := os.Stat(filepath.Join(c.backupDir, c.idName+".json"))
		require.True(t, os.IsNotExist(statErr))
		_, statErr = os.Stat(filepath.Join(c.backupDir, "config.json"))
		require.NoError(t, statErr)
	})
}

func assertIdentityUnchanged(t *testing.T, identityFile string, enrolledIdentity []byte) {
	identityAfterRecovery, err := os.ReadFile(identityFile)
	require.NoError(t, err)
	require.True(t, bytes.Equal(enrolledIdentity, identityAfterRecovery), "existing identity was overwritten by the backup")
}

// runZetBeforeUpgrade starts ZET, enrolls the context's identity, updates the
// tun IP and log level, waits for the config to write to disk, then stops ZET.
// It returns the saved config as a TunnelStatus struct.
func (c *upgradeContext) runZetBeforeUpgrade(t *testing.T) testutil.TunnelStatus {
	require.NoError(t, c.zet.Start())
	t.Cleanup(c.zet.Stop)

	testutil.FetchAndEnrollJwt(t, state.overlay, c.zet, c.idName)
	c.zet.WaitForControllerEvent(t, "connected", c.idName)

	logLevelResp := c.zet.SetLogLevel(t, "trace")
	logLevelResp.AssertSuccess()

	interfaceData := testutil.InterfaceConfigData{
		L3: testutil.TunIPv4Data{TunIPv4: c.tunIp, TunPrefixLength: 24, AddDns: true},
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
		if parsed && tunnelStatus.TunIpv4 == c.tunIp {
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

