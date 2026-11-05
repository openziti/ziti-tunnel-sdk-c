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

func TestProcessPostureCheck(t *testing.T) {
	t.Run("serviceAccessibleWhileProcessRuns", serviceAccessibleWhileProcessRuns)
}

func TestOSPostureCheck(t *testing.T) {
	t.Run("serviceAccessibleWithPassingOSCheck", serviceAccessibleWithPassingOSCheck)
}

func TestMACPostureCheck(t *testing.T) {
	t.Run("serviceAccessibleWithPassingMacCheck", serviceAccessibleWithPassingMacCheck)
}

func TestPostureCheckAddedWhileRunning(t *testing.T) {
	t.Run("mfaCheckDeniesUntilMfaEnrolled", mfaCheckDeniesUntilMfaEnrolled)
}

// serviceAccessibleWhileProcessRuns gates a dialed service behind a
// process-multi check and a version-pinned OS check (the router matches the
// process check's OS type against OS data, which clients only send for an OS check).
// The service is denied until the checked process starts and revoked after it is killed.
// The service, configs, and policies come from fixture.json
func serviceAccessibleWhileProcessRuns(t *testing.T) {
	requireMultiTunnel(t)
	testutil.RunWithTimeoutOf(t, time.Second*30, func(t *testing.T) {
		procPath := copyPostureProcessBinary(t)
		osSpec := testutil.PostureOSType(t) + ":" + testutil.LocalOSVersion(t)

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
		osSpec := testutil.PostureOSType(t) + ":" + testutil.LocalOSVersion(t)

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

// serviceAccessibleWithPassingMacCheck gates a dialed service behind a MAC
// posture check listing the MAC addresses of the system running the tests and
// proves the dial succeeds. The service, configs, and policies come from fixture.json
func serviceAccessibleWithPassingMacCheck(t *testing.T) {
	requireMultiTunnel(t)
	testutil.RunWithTimeoutOf(t, time.Second*30, func(t *testing.T) {
		macs := testutil.LocalMACAddresses(t)

		clientID := "test_mac_posture_client"
		hostID := "test_mac_posture_host"
		interceptAddr := "100.64.0.22:23002"

		// the fixture's test_mac_posture_host_cfg forwards tunneled connections
		// to 127.0.0.1:23182; this echo server answers them
		testutil.StartTCPEcho(t, "127.0.0.1:23182")
		state.overlay.CreateMacPostureCheck(t, "test_mac_posture_mac", macs, "test-mac-posture")

		testutil.FetchAndEnrollJwt(t, state.overlay, state.zetClient, clientID)
		testutil.FetchAndEnrollJwt(t, state.overlay, state.zetHost, hostID)
		state.zetClient.WaitForControllerEvent(t, "connected", clientID)
		state.zetHost.WaitForControllerEvent(t, "connected", hostID)

		bulk := state.zetClient.WaitForBulkServiceEvent(t, "updated", clientID)
		require.Len(t, bulk.AddedServices, 1, "services added for %s", clientID)
		require.Len(t, bulk.AddedServices[0].PostureChecks, 1)
		require.Equal(t, "MAC", bulk.AddedServices[0].PostureChecks[0].QueryType)

		// don't print the addresses themselves, CI logs are public
		t.Logf("dialing test_mac_posture_svc at %s until allowed (%d local macs on the check)", interceptAddr, len(macs))
		testutil.WaitForServiceAllowed(t, state.zetClient, interceptAddr, 25*time.Second)
	})
}

func mfaCheckDeniesUntilMfaEnrolled(t *testing.T) {
	requireMultiTunnel(t)
	skipOnOidcBeforeZiti2(t)
	testutil.RunWithTimeoutOf(t, 90*time.Second, func(t *testing.T) {
		clientID := "test_posture_added_mfa_client"
		hostID := "test_posture_added_mfa_host"
		interceptAddr := "100.64.0.25:23005"

		// test_posture_added_mfa_host_cfg forwards tunneled connections to 127.0.0.1:23185
		testutil.StartTCPEcho(t, "127.0.0.1:23185")
		added := testutil.FetchAndEnrollJwt(t, state.overlay, state.zetClient, clientID)
		testutil.FetchAndEnrollJwt(t, state.overlay, state.zetHost, hostID)
		state.zetClient.WaitForControllerEvent(t, "connected", clientID)
		state.zetHost.WaitForControllerEvent(t, "connected", hostID)

		bulk := state.zetClient.WaitForBulkServiceEvent(t, "updated", clientID)
		require.Len(t, bulk.AddedServices, 1, "services added for %s", clientID)
		require.Empty(t, bulk.AddedServices[0].PostureChecks)
		testutil.WaitForServiceAllowed(t, state.zetClient, interceptAddr, 25*time.Second)

		// the router enforces the new check at once, ZET only reports it after its next service poll
		state.zetClient.SkipToNow()
		state.overlay.CreateMfaPostureCheck(t, "test_posture_added_mfa_check", "test-posture-added-mfa")
		testutil.WaitForServiceDenied(t, state.zetClient, interceptAddr, 25*time.Second)
		bulk = state.zetClient.WaitForBulkServiceEvent(t, "updated", clientID)
		require.Len(t, bulk.AddedServices, 1, "services changed for %s", clientID)
		require.False(t, bulk.AddedServices[0].IsAccessible)
		require.Len(t, bulk.AddedServices[0].PostureChecks, 1)
		require.Equal(t, "MFA", bulk.AddedServices[0].PostureChecks[0].QueryType)
		require.False(t, bulk.AddedServices[0].PostureChecks[0].IsPassing)

		state.zetClient.EnableMFA(t, added.Id.Identifier).AssertSuccess()
		challenge := state.zetClient.WaitForMfaEvent(t, "enrollment_challenge", clientID)
		challenge.AssertSuccess()
		secret := testutil.ParseTOTPSecret(t, challenge.ProvisioningUrl)
		state.zetClient.VerifyMFA(t, added.Id.Identifier, testutil.GenerateTOTP(t, secret, time.Now())).AssertSuccess()
		state.zetClient.WaitForIdentityEvent(t, "updated", clientID).AssertMfaAuthenticated()

		// the next window's code, so the controller cannot reject it as the one VerifyMFA spent
		code := testutil.GenerateTOTP(t, secret, time.Now().Add(30*time.Second))
		state.zetClient.SubmitMFA(t, added.Id.Identifier, code).AssertSuccess()
		testutil.WaitForServiceAllowed(t, state.zetClient, interceptAddr, 30*time.Second)

		// Inverted until openziti/ziti#4558 is fixed, then pass true.
		waitForMfaPostureService(t, clientID, false)
	})
}

// copyPostureProcessBinary copies a benign long-lived binary to a canonical
// temp path. The check must point at the real path: symlinked or junction
// paths never match the running process.
func copyPostureProcessBinary(t *testing.T) string {
	src := "/bin/sleep"
	// uutils coreutils is one binary that picks the tool from the executed file's
	// name (AT_EXECFN, not argv[0]), so the copy must stay named sleep.
	dstName := "sleep"
	if runtime.GOOS == "windows" {
		src = filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
		dstName = "test_proc_posture.exe"
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
	var output strings.Builder
	proc.Stdout = &output
	proc.Stderr = &output
	require.NoError(t, proc.Start(), "start %s", path)
	// "signal: killed" means it ran until cleanup, an exit status means it died on its own
	t.Cleanup(func() {
		_ = proc.Process.Kill()
		if err := proc.Wait(); t.Failed() {
			t.Logf("posture process %d ended with %v, output %q", proc.Process.Pid, err, output.String())
		}
	})
	return proc
}
