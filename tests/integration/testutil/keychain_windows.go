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

package testutil

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Providers tlsuv tries: TPM-backed first, software fallback for CI runners.
const keychainProviders = `'Microsoft Platform Crypto Provider','Microsoft Software Key Storage Provider'`

func KeychainKeyExists(t *testing.T, keyRef string) bool {
	out := runPowerShell(t, fmt.Sprintf(`$n=%s
$found=$false
foreach ($name in %s) {
  try {
    $p=[System.Security.Cryptography.CngProvider]::new($name)
    if ([System.Security.Cryptography.CngKey]::Exists($n,$p,[System.Security.Cryptography.CngKeyOpenOptions]::UserKey)) { $found=$true; break }
  } catch { }
}
$found`, psQuote(strings.TrimPrefix(keyRef, "keychain:")), keychainProviders))
	return strings.EqualFold(strings.TrimSpace(out), "True")
}

func RemoveKeychainKey(t *testing.T, keyRef string) {
	runPowerShell(t, fmt.Sprintf(`$n=%s
foreach ($name in %s) {
  try {
    $p=[System.Security.Cryptography.CngProvider]::new($name)
    if ([System.Security.Cryptography.CngKey]::Exists($n,$p,[System.Security.Cryptography.CngKeyOpenOptions]::UserKey)) { [System.Security.Cryptography.CngKey]::Open($n,$p).Delete() }
  } catch { }
}`, psQuote(strings.TrimPrefix(keyRef, "keychain:")), keychainProviders))
}

func runPowerShell(t *testing.T, script string) string {
	out, err := exec.Command("powershell", "-NoProfile", "-Command", script).CombinedOutput()
	require.NoError(t, err, "powershell failed: %s\noutput: %s", script, out)
	return string(out)
}

func psQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func AssertKeychainKeyRef(t *testing.T, path string) string {
	content := ReadIdentityFile(t, path)
	require.True(t, strings.HasPrefix(content.ID.Key, "keychain:"), "id.key should be a keychain ref, got %q", content.ID.Key)
	require.NotContains(t, content.ID.Key, "PRIVATE KEY", "id.key should not embed key material: %q", content.ID.Key)
	return content.ID.Key
}
