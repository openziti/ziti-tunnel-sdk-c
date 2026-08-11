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
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/openziti/ziti-tunnel-sdk-c/tests/integration/testutil"
	"github.com/stretchr/testify/require"
)

func TestProcessPostureCheck(t *testing.T) {
	t.Run("serviceAccessibleWhileProcessRuns", serviceAccessibleWhileProcessRuns)
}

// serviceAccessibleWhileProcessRuns gates a dialed service behind a
// process-multi check and a version-pinned OS check (clients only send process
// posture data when an OS check is on the same policy). The service is denied
// until the checked process starts and revoked after it is killed.
func serviceAccessibleWhileProcessRuns(t *testing.T) {
	requireMultiTunnel(t)
	testutil.RunWithTimeoutOf(t, 3*time.Minute, func(t *testing.T) {
		procPath := copyPostureProcessBinary(t)
		osType := postureOSType(t)
		osVersion := runnerOSVersion(t)
		osSpec := osType + ":" + osVersion

		echo := testutil.StartTCPEcho(t)
		_, echoPortStr, err := net.SplitHostPort(echo.Addr)
		require.NoError(t, err)
		echoPort, err := strconv.Atoi(echoPortStr)
		require.NoError(t, err)

		procCheck := "test_proc_posture_process"
		osCheck := "test_proc_posture_os"
		clientID := "test_proc_posture_client"
		hostID := "test_proc_posture_host"
		hostCfg := "test_proc_posture_host_cfg"
		interceptCfg := "test_proc_posture_intercept_cfg"
		svcName := "test_proc_posture_svc"
		bindPolicy := "test_proc_posture_bind"
		dialPolicy := "test_proc_posture_dial"
		interceptIP := "100.64.0.20"
		interceptPort := 23000

		state.overlay.CreateProcessMultiPostureCheck(t, procCheck, osType, procPath)
		state.overlay.CreateOSPostureCheck(t, osCheck, osSpec)

		testutil.FetchAndEnrollJwt(t, state.overlay, state.zetClient, clientID)
		testutil.FetchAndEnrollJwt(t, state.overlay, state.zetHost, hostID)
		state.zetClient.WaitForControllerEvent(t, "connected", clientID)
		state.zetHost.WaitForControllerEvent(t, "connected", hostID)

		require.NoError(t, state.overlay.CreateHostConfigV1(hostCfg, "tcp", "127.0.0.1", echoPort))
		require.NoError(t, state.overlay.CreateInterceptConfigV1(interceptCfg, []string{"tcp"}, []string{interceptIP + "/32"}, interceptPort, interceptPort))
		require.NoError(t, state.overlay.CreateService(svcName, []string{hostCfg, interceptCfg}))
		require.NoError(t, state.overlay.CreateBindServicePolicy(bindPolicy, hostID, svcName))
		require.NoError(t, state.overlay.CreateDialServicePolicy(dialPolicy, clientID, svcName, procCheck, osCheck))

		bulk := state.zetClient.WaitForBulkServiceEvent(t, "updated", clientID)
		require.Len(t, bulk.AddedServices, 1, "services added for %s", clientID)
		require.False(t, bulk.AddedServices[0].IsAccessible)
		require.Len(t, bulk.AddedServices[0].PostureChecks, 2)
		var processCheck *testutil.PostureCheck
		for i, check := range bulk.AddedServices[0].PostureChecks {
			if check.QueryType == "PROCESS_MULTI" {
				processCheck = &bulk.AddedServices[0].PostureChecks[i]
			}
		}
		require.NotNil(t, processCheck, "no PROCESS_MULTI posture check on %s", svcName)
		require.False(t, processCheck.IsPassing)

		interceptAddr := net.JoinHostPort(interceptIP, strconv.Itoa(interceptPort))
		require.Error(t, tryEcho(interceptAddr), "service should be denied while %s is not running", procPath)

		proc := startPostureProcess(t, procPath)
		t.Logf("started %s (pid %d), dialing %s at %s until allowed", procPath, proc.Process.Pid, svcName, interceptAddr)
		waitForServiceAllowed(t, interceptAddr, 60*time.Second)

		require.NoError(t, proc.Process.Kill())
		_ = proc.Wait()
		t.Logf("killed pid %d, dialing %s at %s until denied", proc.Process.Pid, svcName, interceptAddr)
		waitForServiceDenied(t, interceptAddr, 60*time.Second)
	})
}

// copyPostureProcessBinary copies a benign long-lived binary to a canonical
// temp path. The check must point at the real path: symlinked or junction
// paths never match the running process.
func copyPostureProcessBinary(t *testing.T) string {
	src := "/bin/sleep"
	dstName := "test_proc_posture"
	if runtime.GOOS == "windows" {
		src = filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
		dstName += ".exe"
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err, "resolve temp dir")
	data, err := os.ReadFile(src)
	require.NoError(t, err, "read %s", src)
	dst := filepath.Join(dir, dstName)
	require.NoError(t, os.WriteFile(dst, data, 0o755), "write %s", dst)
	return dst
}

// postureOSType maps runtime.GOOS to the posture check OS type.
func postureOSType(t *testing.T) string {
	switch runtime.GOOS {
	case "windows":
		return "windows"
	case "linux":
		return "linux"
	case "darwin":
		return "macos"
	default:
		t.Fatalf("no posture OS type for %s", runtime.GOOS)
		return ""
	}
}

// runnerOSVersion returns the version string the C SDK reports in posture
// data (posture.c): windows sends major.minor.build from RtlGetVersion,
// everything else sends the uname release.
func runnerOSVersion(t *testing.T) string {
	if runtime.GOOS != "windows" {
		out, err := exec.Command("uname", "-r").Output()
		require.NoError(t, err, "uname -r")
		return strings.TrimSpace(string(out))
	}
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
}

// startPostureProcess launches the copied binary and registers cleanup to kill
// it. cmd.exe is held alive by its stdin pipe; sleep by its duration argument.
func startPostureProcess(t *testing.T, path string) *exec.Cmd {
	var proc *exec.Cmd
	if runtime.GOOS == "windows" {
		proc = exec.Command(path)
		stdin, err := proc.StdinPipe()
		require.NoError(t, err, "stdin pipe for %s", path)
		t.Cleanup(func() { _ = stdin.Close() })
	} else {
		proc = exec.Command(path, "300")
	}
	require.NoError(t, proc.Start(), "start %s", path)
	t.Cleanup(func() { _ = proc.Process.Kill() })
	return proc
}

// tryEcho round-trips one payload through the intercepted service.
func tryEcho(addr string) error {
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
	if _, err := readFull(conn, got); err != nil {
		return err
	}
	if !bytes.Equal(payload, got) {
		return fmt.Errorf("echo mismatch: got %q", got)
	}
	return nil
}

// waitForServiceAllowed polls until an echo round trip succeeds. Every dial
// attempt resends posture data, so polling drives the transition itself.
func waitForServiceAllowed(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var err error
	for time.Now().Before(deadline) {
		if err = tryEcho(addr); err == nil {
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("service at %s still denied after %s: %v\nzetA: %s", addr, timeout, err, state.zetClient.LogFile())
}

// waitForServiceDenied polls until an echo round trip fails.
func waitForServiceDenied(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := tryEcho(addr); err != nil {
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("service at %s still accessible after %s\nzetA: %s", addr, timeout, state.zetClient.LogFile())
}
