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

func TestPostureCheck(t *testing.T) {
	t.Run("serviceAccessibleWhileProcessRuns", serviceAccessibleWhileProcessRuns)
	t.Run("serviceAccessibleWithPassingOSCheck", serviceAccessibleWithPassingOSCheck)
	t.Run("serviceAccessibleWithPassingMacCheck", serviceAccessibleWithPassingMacCheck)
	t.Run("mfaCheckDeniesUntilMfaEnrolled", mfaCheckDeniesUntilMfaEnrolled)
}

func serviceAccessibleWhileProcessRuns(t *testing.T) {
	requireMultiTunnel(t)
	testutil.RunWithTimeoutOf(t, time.Second*30, func(t *testing.T) {
		procPath := copyPostureProcessBinary(t)
		osType := testutil.PostureOSType(t)
		osSpec := osType + ":" + testutil.LocalOSVersion(t)

		clientID := "test_proc_posture_client"
		hostID := "test_proc_posture_host"
		svcName := "test_proc_posture_svc"
		interceptAddr := "100.64.0.20:23000"

		state.overlay.CreateProcessMultiPostureCheck(t, "test_proc_posture_process", osType, procPath, "test-proc-posture")
		// the router matches the process check's OS type against OS data, which clients only send for an OS check
		state.overlay.CreateOSPostureCheck(t, "test_proc_posture_os", osSpec, "test-proc-posture")
		_, bulk := enrollAndStartEcho(t, clientID, hostID, "127.0.0.1:23180")
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

		postureProcess := startPostureProcess(t, procPath)
		t.Logf("started %s (pid %d), dialing %s at %s until allowed", procPath, postureProcess.Process.Pid, svcName, interceptAddr)
		testutil.WaitForServiceAllowed(interceptAddr)

		require.NoError(t, postureProcess.Process.Kill())
		_ = postureProcess.Wait()
		t.Logf("killed pid %d, dialing %s at %s until denied", postureProcess.Process.Pid, svcName, interceptAddr)
		testutil.WaitForServiceDenied(interceptAddr)
	})
}

func serviceAccessibleWithPassingOSCheck(t *testing.T) {
	requireMultiTunnel(t)
	testutil.RunWithTimeoutOf(t, time.Second*30, func(t *testing.T) {
		osSpec := testutil.PostureOSType(t) + ":" + testutil.LocalOSVersion(t)

		clientID := "test_os_posture_client"
		hostID := "test_os_posture_host"
		interceptAddr := "100.64.0.21:23001"

		state.overlay.CreateOSPostureCheck(t, "test_os_posture_os", osSpec, "test-os-posture")
		_, bulk := enrollAndStartEcho(t, clientID, hostID, "127.0.0.1:23181")
		require.Len(t, bulk.AddedServices[0].PostureChecks, 1)
		require.Equal(t, "OS", bulk.AddedServices[0].PostureChecks[0].QueryType)

		t.Logf("dialing test_os_posture_svc at %s until allowed (os check %s)", interceptAddr, osSpec)
		testutil.WaitForServiceAllowed(interceptAddr)
	})
}

func serviceAccessibleWithPassingMacCheck(t *testing.T) {
	requireMultiTunnel(t)
	testutil.RunWithTimeoutOf(t, time.Second*30, func(t *testing.T) {
		macs := testutil.LocalMACAddresses(t)

		clientID := "test_mac_posture_client"
		hostID := "test_mac_posture_host"
		interceptAddr := "100.64.0.22:23002"

		state.overlay.CreateMacPostureCheck(t, "test_mac_posture_mac", macs, "test-mac-posture")
		_, bulk := enrollAndStartEcho(t, clientID, hostID, "127.0.0.1:23182")
		require.Len(t, bulk.AddedServices[0].PostureChecks, 1)
		require.Equal(t, "MAC", bulk.AddedServices[0].PostureChecks[0].QueryType)

		// don't print the addresses themselves, CI logs are public
		t.Logf("dialing test_mac_posture_svc at %s until allowed (%d local macs on the check)", interceptAddr, len(macs))
		testutil.WaitForServiceAllowed(interceptAddr)
	})
}

func mfaCheckDeniesUntilMfaEnrolled(t *testing.T) {
	requireMultiTunnel(t)
	skipOnOidcBeforeZiti2(t)
	testutil.RunWithTimeoutOf(t, 90*time.Second, func(t *testing.T) {
		clientID := "test_posture_added_mfa_client"
		hostID := "test_posture_added_mfa_host"
		interceptAddr := "100.64.0.25:23005"

		added, bulk := enrollAndStartEcho(t, clientID, hostID, "127.0.0.1:23185")
		require.Empty(t, bulk.AddedServices[0].PostureChecks)
		testutil.WaitForServiceAllowed(interceptAddr)

		// the router enforces the new check at once, ZET only reports it after its next service poll
		state.zetClient.SkipToNow()
		state.overlay.CreateMfaPostureCheck(t, "test_posture_added_mfa_check", "test-posture-added-mfa")
		testutil.WaitForServiceDenied(interceptAddr)
		bulk = state.zetClient.WaitForBulkServiceEvent(t, "updated", clientID)
		require.Len(t, bulk.AddedServices, 1, "services changed for %s", clientID)
		require.False(t, bulk.AddedServices[0].IsAccessible)
		require.Len(t, bulk.AddedServices[0].PostureChecks, 1)
		require.Equal(t, "MFA", bulk.AddedServices[0].PostureChecks[0].QueryType)
		require.False(t, bulk.AddedServices[0].PostureChecks[0].IsPassing)

		enableResp := state.zetClient.EnableMFA(t, added.Id.Identifier)
		enableResp.AssertSuccess()
		challenge := state.zetClient.WaitForMfaEvent(t, "enrollment_challenge", clientID)
		challenge.AssertSuccess()
		secret := testutil.ParseTOTPSecret(t, challenge.ProvisioningUrl)
		verifyResp := state.zetClient.VerifyMFA(t, added.Id.Identifier, testutil.GenerateTOTP(t, secret, time.Now()))
		verifyResp.AssertSuccess()
		updatedEvent := state.zetClient.WaitForIdentityEvent(t, "updated", clientID)
		updatedEvent.AssertMfaAuthenticated()

		// the next window's code, so the controller cannot reject it as the one VerifyMFA spent
		code := testutil.GenerateTOTP(t, secret, time.Now().Add(30*time.Second))
		submitResp := state.zetClient.SubmitMFA(t, added.Id.Identifier, code)
		submitResp.AssertSuccess()
		testutil.WaitForServiceAllowed(interceptAddr)
		waitForMfaPostureService(t, clientID)
	})
}

// echoAddr is where the fixture.json host config of hostID forwards tunneled connections.
func enrollAndStartEcho(t *testing.T, clientID, hostID, echoAddr string) (testutil.IdentityEvent, testutil.BulkServiceEvent) {
	t.Helper()
	// client first: on ziti 1.x the SDK drops posture data sent before the client's router channel connects
	added := testutil.FetchAndEnrollJwt(t, state.overlay, state.zetClient, clientID)
	testutil.FetchAndEnrollJwt(t, state.overlay, state.zetHost, hostID)
	state.zetHost.WaitForControllerEvent(t, "connected", hostID)
	state.zetClient.WaitForControllerEvent(t, "connected", clientID)
	bulk := state.zetClient.WaitForBulkServiceEvent(t, "updated", clientID)
	require.Len(t, bulk.AddedServices, 1, "services added for %s", clientID)
	testutil.StartTCPEcho(t, echoAddr)
	return added, bulk
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
	var postureProcess *exec.Cmd
	if runtime.GOOS == "windows" {
		postureProcess = exec.Command(path)
		stdin, err := postureProcess.StdinPipe()
		require.NoError(t, err, "stdin pipe for %s", path)
		t.Cleanup(func() { _ = stdin.Close() })
	} else {
		postureProcess = exec.Command(path, "300")
	}
	var output strings.Builder
	postureProcess.Stdout = &output
	postureProcess.Stderr = &output
	require.NoError(t, postureProcess.Start(), "start %s", path)
	// "signal: killed" means it ran until cleanup, an exit status means it died on its own
	t.Cleanup(func() {
		if postureProcess.ProcessState != nil {
			return
		}
		_ = postureProcess.Process.Kill()
		if err := postureProcess.Wait(); t.Failed() {
			t.Logf("posture process %d ended with %v, output %q", postureProcess.Process.Pid, err, output.String())
		}
	})
	return postureProcess
}
