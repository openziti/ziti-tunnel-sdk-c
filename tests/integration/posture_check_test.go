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
	"testing"
	"time"

	"github.com/openziti/ziti-tunnel-sdk-c/tests/integration/testutil"
	"github.com/stretchr/testify/require"
)

func TestProcessPostureCheck(t *testing.T) {
	t.Run("serviceAccessibleWhileProcessRuns", serviceAccessibleWhileProcessRuns)
}

func TestOSPostureCheck(t *testing.T) {
	t.Run("serviceAccessibleWithPassingOSCheck", serviceAccessibleWithPassingOSCheck)
}

// serviceAccessibleWhileProcessRuns gates a dialed service behind a
// process-multi check and a version-pinned OS check (clients only send process
// posture data when an OS check is on the same policy at the moment).
// The service is denied until the checked process starts and revoked after it is killed.
// The service, configs, and policies come from fixture.json
func serviceAccessibleWhileProcessRuns(t *testing.T) {
	requireMultiTunnel(t)
	testutil.RunWithTimeoutOf(t, time.Second*30, func(t *testing.T) {
		procPath := copyPostureProcessBinary(t)
		osSpec := testutil.PostureOSType(t) + ":" + testutil.RunnerOSVersion(t)

		clientID := "test_proc_posture_client"
		hostID := "test_proc_posture_host"
		svcName := "test_proc_posture_svc"
		interceptAddr := "100.64.0.20:23000"

		// the fixture's test_proc_posture_host_cfg forwards tunneled connections
		// to 127.0.0.1:23180; this echo server answers them
		testutil.StartTCPEcho(t, "127.0.0.1:23180")
		state.overlay.CreateProcessMultiPostureCheck(t, "test_proc_posture_process", testutil.PostureOSType(t), procPath, "test-proc-posture")
		state.overlay.CreateOSPostureCheck(t, "test_proc_posture_os", osSpec, "test-proc-posture")

		testutil.FetchAndEnrollJwt(t, state.overlay, state.zetClient, clientID)
		testutil.FetchAndEnrollJwt(t, state.overlay, state.zetHost, hostID)
		state.zetClient.WaitForControllerEvent(t, "connected", clientID)
		state.zetHost.WaitForControllerEvent(t, "connected", hostID)

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

		require.Error(t, testutil.TryEcho(interceptAddr), "service should be denied while %s is not running", procPath)

		proc := startPostureProcess(t, procPath)
		t.Logf("started %s (pid %d), dialing %s at %s until allowed", procPath, proc.Process.Pid, svcName, interceptAddr)
		testutil.WaitForServiceAllowed(t, state.zetClient, interceptAddr, 25*time.Second)

		require.NoError(t, proc.Process.Kill())
		_ = proc.Wait()
		t.Logf("killed pid %d, dialing %s at %s until denied", proc.Process.Pid, svcName, interceptAddr)
		testutil.WaitForServiceDenied(t, state.zetClient, interceptAddr, 25*time.Second)
	})
}

// serviceAccessibleWithPassingOSCheck gates a dialed service behind an OS posture check
// The service, configs, and policies come from the fixture.json
func serviceAccessibleWithPassingOSCheck(t *testing.T) {
	requireMultiTunnel(t)
	testutil.RunWithTimeoutOf(t, time.Second*30, func(t *testing.T) {
		osSpec := testutil.PostureOSType(t) + ":" + testutil.RunnerOSVersion(t)

		clientID := "test_os_posture_client"
		hostID := "test_os_posture_host"
		interceptAddr := "100.64.0.21:23001"

		// the fixture's test_os_posture_host_cfg forwards tunneled connections
		// to 127.0.0.1:23181; this echo server answers them
		testutil.StartTCPEcho(t, "127.0.0.1:23181")
		state.overlay.CreateOSPostureCheck(t, "test_os_posture_os", osSpec, "test-os-posture")

		testutil.FetchAndEnrollJwt(t, state.overlay, state.zetClient, clientID)
		testutil.FetchAndEnrollJwt(t, state.overlay, state.zetHost, hostID)
		state.zetClient.WaitForControllerEvent(t, "connected", clientID)
		state.zetHost.WaitForControllerEvent(t, "connected", hostID)

		bulk := state.zetClient.WaitForBulkServiceEvent(t, "updated", clientID)
		require.Len(t, bulk.AddedServices, 1, "services added for %s", clientID)
		require.Len(t, bulk.AddedServices[0].PostureChecks, 1)
		require.Equal(t, "OS", bulk.AddedServices[0].PostureChecks[0].QueryType)

		t.Logf("dialing test_os_posture_svc at %s until allowed (os check %s)", interceptAddr, osSpec)
		testutil.WaitForServiceAllowed(t, state.zetClient, interceptAddr, 25*time.Second)
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
