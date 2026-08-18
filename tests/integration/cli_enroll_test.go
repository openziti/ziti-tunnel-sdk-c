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
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/openziti/ziti-tunnel-sdk-c/tests/integration/testutil"
	"github.com/stretchr/testify/require"
)

// `ziti-edge-tunnel enroll` as its own process. Every other test here enrolls through the IPC
// AddIdentity command inside a running daemon; the container entrypoint runs the subcommand,
// so this is the only coverage of that path.
//
// These assert on how the process exited, not just on whether an identity appeared, so a crash
// is reported as a crash.
func TestCliEnroll(t *testing.T) {
	t.Run("enrollsWithValidJwt", cliEnrollsWithValidJwt)
	t.Run("rejectsMalformedJwtWithoutCrashing", cliEnrollRejectsMalformedJwt)
}

// The happy path the container entrypoint runs: a real one-time token against a live
// controller, ending in a usable identity file.
func cliEnrollsWithValidJwt(t *testing.T) {
	testutil.RunWithTimeoutOf(t, 60*time.Second, func(t *testing.T) {
		idName := "test_cli_enroll"
		jwt := state.overlay.GetJwtFromController(t, idName)

		dir := t.TempDir()
		jwtPath := filepath.Join(dir, idName+".jwt")
		require.NoError(t, os.WriteFile(jwtPath, []byte(jwt), 0o600), "write jwt")
		idPath := filepath.Join(dir, idName+".json")

		out, err := runEnroll(t, "--jwt", jwtPath, "--identity", idPath)
		requireNotSignalled(t, err, out)
		require.NoError(t, err, "enroll exited non-zero\n%s", out)

		testutil.AssertValidJwtEnrolledIdentityFile(t, idPath)
	})
}

// A token that parses as three base64url segments but is not a real enrollment token. The
// point is the manner of failure: a non-zero exit with a message, never a crash.
func cliEnrollRejectsMalformedJwt(t *testing.T) {
	testutil.RunWithTimeoutOf(t, 60*time.Second, func(t *testing.T) {
		dir := t.TempDir()
		jwtPath := filepath.Join(dir, "malformed.jwt")
		require.NoError(t, os.WriteFile(jwtPath, []byte(malformedJwt), 0o600), "write jwt")
		idPath := filepath.Join(dir, "malformed.json")

		out, err := runEnroll(t, "--jwt", jwtPath, "--identity", idPath)
		requireNotSignalled(t, err, out)
		require.Error(t, err, "enroll accepted a malformed token\n%s", out)
		require.NoFileExists(t, idPath, "enroll wrote an identity file for a malformed token")
	})
}

// runEnroll runs the tunneler's enroll subcommand and returns its combined output.
func runEnroll(t *testing.T, args ...string) (string, error) {
	bin := state.zetClient.BinPath
	require.FileExists(t, bin, "ziti-edge-tunnel binary")

	cmd := exec.Command(bin, append([]string{"enroll"}, args...)...)
	out, err := cmd.CombinedOutput()
	t.Logf("%s enroll %s -> %v", filepath.Base(bin), strings.Join(args, " "), err)
	return string(out), err
}

// requireNotSignalled fails when the process died on a signal rather than exiting. Kept
// separate from a non-zero exit: one is the program deciding, the other is it crashing.
func requireNotSignalled(t *testing.T, err error, out string) {
	t.Helper()
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		return
	}
	status := exitErr.ProcessState.String()
	// "signal: segmentation fault" on unix; Windows reports the exception as the exit code
	require.NotContains(t, status, "signal:", "enroll crashed (%s)\n%s", status, out)
	if runtime.GOOS == "windows" {
		// 0xC0000005 is STATUS_ACCESS_VIOLATION; go reports it as a large exit code
		require.NotEqual(t, 0xC0000005, uint32(exitErr.ExitCode()),
			"enroll crashed with an access violation\n%s", out)
	}
}

// A syntactically well-formed JWT (header.payload.signature, all base64url) that is not a
// valid enrollment token, so it parses and then fails.
const malformedJwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImQ2ZWRhMWI3MDhiN2YwNzIyM2ZhYzZkYjJiZGIzY2YxOGZkZTRkZjkiLCJ0eXAiOiJKV1QifQ." +
	"eyJpc3MiOiJodHRwczovL2xvY2FsaG9zdDoxMjgwIiwic3ViIjoiVzRrRXJmc0I2YSIsImF1ZCI6WyIiXSwiZXhwIjoxNzg3MDgyMDQxfQ." +
	"ST5oQsFMU058gZB2HoUwJqghQM00J97upUR28RD0r8eV5B5wQgO_PeIXK4LCx544bUBdAx6x"
