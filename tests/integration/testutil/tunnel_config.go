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

package testutil

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// IdentityDir is the -I sandbox this instance loads identities and config.json from.
func (z *ZET) IdentityDir() string {
	return filepath.Join(z.RootDir, "identities")
}

// TunnelConfigPath is the tunnel status file the tunneler persists identity state to.
func (z *ZET) TunnelConfigPath() string {
	return filepath.Join(z.IdentityDir(), "config.json")
}

// ReadTunnelConfig returns the persisted tunnel status as a generic map, so tests can
// assert on fields without pinning the whole schema.
//
// The tunneler rewrites this file in place rather than writing a temporary file and
// renaming it, so a reader can catch it truncated or half-written.
func (z *ZET) ReadTunnelConfig(t *testing.T) map[string]any {
	path := z.TunnelConfigPath()
	deadline := time.Now().Add(5 * time.Second)

	var lastErr error
	for {
		raw, err := os.ReadFile(path)
		if err == nil {
			var cfg map[string]any
			if err = json.Unmarshal(raw, &cfg); err == nil {
				return cfg
			}
		}
		lastErr = err
		if time.Now().After(deadline) {
			require.NoError(t, lastErr, "read %s; still unreadable after 5s", path)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// PersistedIdentity returns the persisted entry for identifier from config.json.
func (z *ZET) PersistedIdentity(t *testing.T, identifier string) map[string]any {
	cfg := z.ReadTunnelConfig(t)
	identities, ok := cfg["Identities"].([]any)
	require.True(t, ok, "config.json has no Identities array")

	for _, entry := range identities {
		identity, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		if identity["Identifier"] == identifier {
			return identity
		}
	}
	require.FailNowf(t, "identity missing from config.json", "identifier=%s", identifier)
	return nil
}

// SetPersistedMfaEnabled rewrites MfaEnabled for identifier in config.json. The
// tunneler must not be running: it holds this state in memory and overwrites the file.
func (z *ZET) SetPersistedMfaEnabled(t *testing.T, identifier string, enabled bool) {
	cfg := z.ReadTunnelConfig(t)
	identities, ok := cfg["Identities"].([]any)
	require.True(t, ok, "config.json has no Identities array")

	found := false
	for _, entry := range identities {
		identity, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		if identity["Identifier"] == identifier {
			identity["MfaEnabled"] = enabled
			found = true
		}
	}
	require.True(t, found, "identity %s missing from config.json", identifier)

	raw, err := json.MarshalIndent(cfg, "", "    ")
	require.NoError(t, err, "encode config.json")
	require.NoError(t, os.WriteFile(z.TunnelConfigPath(), raw, 0o600), "write %s", z.TunnelConfigPath())
}
