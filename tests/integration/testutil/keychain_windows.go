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

var keychainProviders = []string{
	"Microsoft Platform Crypto Provider",
	"Microsoft Software Key Storage Provider",
}

func KeychainKeyExists(t *testing.T, keyRef string) bool {
	name := strings.TrimPrefix(keyRef, "keychain:")
	for _, p := range keychainProviders {
		out := runPowerShell(t, fmt.Sprintf(
			`[System.Security.Cryptography.CngKey]::Exists(%s,[System.Security.Cryptography.CngProvider]::new(%s),[System.Security.Cryptography.CngKeyOpenOptions]::UserKey)`,
			psQuote(name), psQuote(p)))
		if strings.EqualFold(strings.TrimSpace(out), "True") {
			return true
		}
	}
	return false
}

func RemoveKeychainKey(t *testing.T, keyRef string) {
	name := strings.TrimPrefix(keyRef, "keychain:")
	for _, p := range keychainProviders {
		runPowerShell(t, fmt.Sprintf(
			`$n=%s
$p=[System.Security.Cryptography.CngProvider]::new(%s)
if ([System.Security.Cryptography.CngKey]::Exists($n,$p,[System.Security.Cryptography.CngKeyOpenOptions]::UserKey)) { [System.Security.Cryptography.CngKey]::Open($n,$p).Delete() }`,
			psQuote(name), psQuote(p)))
	}
}

func runPowerShell(t *testing.T, script string) string {
	out, err := exec.Command("powershell", "-NoProfile", "-Command", script).CombinedOutput()
	require.NoError(t, err, "powershell failed: %s\noutput: %s", script, out)
	return string(out)
}

func psQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
