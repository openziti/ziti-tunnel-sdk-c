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
	"bytes"
	"fmt"
	"io"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// PostureOSType returns the posture check OS type the C SDK will report.
// Server product types report windowsserver, not windows (posture.c), which
// is what CI runners are.
func PostureOSType(t *testing.T) string {
	switch runtime.GOOS {
	case "windows":
		out, err := exec.Command("powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_OperatingSystem).ProductType").Output()
		require.NoError(t, err, "read windows product type")
		if strings.TrimSpace(string(out)) == "1" {
			return "windows"
		}
		return "windowsserver"
	case "linux":
		return "linux"
	case "darwin":
		return "macos"
	default:
		t.Fatalf("no posture OS type for %s", runtime.GOOS)
		return ""
	}
}

// RunnerOSVersion returns the version string the C SDK reports in posture
// data: windows sends major.minor.build (posture.c RtlGetVersion), macOS
// sends the product version (sdk_info.c kern.osproductversion), linux sends
// the uname release.
func RunnerOSVersion(t *testing.T) string {
	switch runtime.GOOS {
	case "windows":
		out, err := exec.Command("cmd", "/c", "ver").Output()
		require.NoError(t, err, "cmd /c ver")
		// "Microsoft Windows [Version 10.0.26200.5074]" -> "10.0.26200"
		verText := string(out)
		start := strings.Index(verText, "[Version ")
		require.NotEqual(t, -1, start, "unexpected ver output %q", verText)
		verText = verText[start+len("[Version "):]
		end := strings.Index(verText, "]")
		require.NotEqual(t, -1, end, "unexpected ver output %q", verText)
		parts := strings.Split(verText[:end], ".")
		require.GreaterOrEqual(t, len(parts), 3, "unexpected version %q", verText[:end])
		return strings.Join(parts[:3], ".")
	case "darwin":
		out, err := exec.Command("sw_vers", "-productVersion").Output()
		require.NoError(t, err, "sw_vers -productVersion")
		return strings.TrimSpace(string(out))
	default:
		out, err := exec.Command("uname", "-r").Output()
		require.NoError(t, err, "uname -r")
		return strings.TrimSpace(string(out))
	}
}

// TryEcho round-trips one payload through the intercepted service.
func TryEcho(addr string) error {
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	payload := []byte("posture-probe")
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		return err
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		return err
	}
	if !bytes.Equal(payload, got) {
		return fmt.Errorf("echo mismatch: got %q", got)
	}
	return nil
}

// WaitForServiceAllowed polls until an echo round trip succeeds. Every dial
// attempt resends posture data, so polling drives the transition itself.
func WaitForServiceAllowed(t *testing.T, zet *ZET, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var err error
	for time.Now().Before(deadline) {
		if err = TryEcho(addr); err == nil {
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("service at %s still denied after %s: %v\nzet: %s", addr, timeout, err, zet.LogFile())
}

// WaitForServiceDenied polls until an echo round trip fails.
func WaitForServiceDenied(t *testing.T, zet *ZET, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := TryEcho(addr); err != nil {
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("service at %s still accessible after %s\nzet: %s", addr, timeout, zet.LogFile())
}
