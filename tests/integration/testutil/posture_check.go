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

// PostureOSType returns the posture check OS type of the system running the
// tests. Windows server SKUs report windowsserver, not windows.
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

// LocalOSVersion returns the OS version of the system running the tests as
// ZET reports it: major.minor.build on windows, the product version on macOS,
// the uname release on linux.
func LocalOSVersion(t *testing.T) string {
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

// LocalMACAddresses returns the MAC addresses of the non-internal interfaces
// on the system running the tests, in lowercase hex with no separators.
func LocalMACAddresses(t *testing.T) []string {
	ifaces, err := net.Interfaces()
	require.NoError(t, err, "list network interfaces")
	seen := map[string]struct{}{}
	var macs []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || len(iface.HardwareAddr) == 0 {
			continue
		}
		mac := strings.ToLower(strings.ReplaceAll(iface.HardwareAddr.String(), ":", ""))
		if strings.Trim(mac, "0") == "" {
			continue
		}
		if _, ok := seen[mac]; ok {
			continue
		}
		seen[mac] = struct{}{}
		macs = append(macs, mac)
	}
	require.NotEmpty(t, macs, "no usable MAC addresses on this host")
	return macs
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
