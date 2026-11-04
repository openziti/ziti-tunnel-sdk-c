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

// MfaNeeded for an identity whose services sit behind an MFA posture check with a timeout.

package integration_test

import (
	"testing"
	"time"

	"github.com/openziti/ziti-tunnel-sdk-c/tests/integration/testutil"
	"github.com/stretchr/testify/require"
)

// The timeouts of the MFA posture checks in testdata/fixture.json. The SDK reports the code as
// "expiring" for the last half of a timeout this short.
const (
	mfaCheckTimeout       = 30 * time.Second
	mfaReauthCheckTimeout = 60 * time.Second
)

func TestMFAPostureCheckTimeout(t *testing.T) {
	t.Run("mfaNeededOnlyAfterCodeTimesOut", mfaNeededOnlyAfterCodeTimesOut)
	t.Run("renewedCodeTimesOutToo", renewedCodeTimesOutToo)
	t.Run("reauthPromptStaysUntilCode", reauthPromptStaysUntilCode)
}

// MfaNeeded tells the UI that the services are locked. While the code is merely about to run
// out the services still work, so MfaNeeded has to stay false until the code has run out.
func mfaNeededOnlyAfterCodeTimesOut(t *testing.T) {
	testutil.RunWithTimeoutOf(t, 90*time.Second, func(t *testing.T) {
		idName := "test_mfa_posture_timeout"
		p := setUpMfaPostureService(t, idName, mfaCheckTimeout)

		// well into the time the code is expiring, but before it runs out
		checkAt := p.afterCode.Add(mfaCheckTimeout/2 + 3*time.Second)
		require.True(t, checkAt.Before(p.beforeCode.Add(mfaCheckTimeout-3*time.Second)),
			"enrollment took %s: too long to check the expiring window before the code runs out", p.afterCode.Sub(p.beforeCode))
		time.Sleep(time.Until(checkAt))
		identity := statusIdentity(t, p.identifier)
		// waiting for the service can run past checkAt: then the status may be from after the code ran out
		require.True(t, time.Now().Before(p.beforeCode.Add(mfaCheckTimeout)),
			"status read %s after the code, past its %s timeout: the service took too long to show up",
			time.Since(p.beforeCode), mfaCheckTimeout)
		require.False(t, identity.MfaNeeded, "MfaNeeded=true for %q while its code has not run out", idName)

		// once the code runs out, the tunneler says so on its own
		waitForMfaNeededNotBefore(t, idName, p.beforeCode.Add(mfaCheckTimeout))
	})
}

// A code submitted for the posture check after the last one ran out unlocks the identity, and
// runs out in turn. The SDK reports the new code (PC_MFA event) before the result of the
// submit, so the result must not be taken for the stale code of a login.
func renewedCodeTimesOutToo(t *testing.T) {
	testutil.RunWithTimeoutOf(t, 150*time.Second, func(t *testing.T) {
		idName := "test_mfa_posture_renewal"
		p := setUpMfaPostureService(t, idName, mfaCheckTimeout)

		waitForMfaNeededNotBefore(t, idName, p.beforeCode.Add(mfaCheckTimeout))

		// the code is 30s after the last one at least: another TOTP step, so the controller takes it
		state.zetClient.SkipToNow()
		beforeRenewal := time.Now()
		code := testutil.GenerateTOTP(t, p.secret, beforeRenewal)
		state.zetClient.SubmitMFA(t, p.identifier, code).AssertSuccess()
		for {
			ev := state.zetClient.WaitForIdentityEvent(t, "updated", idName)
			if !ev.Id.MfaNeeded {
				break
			}
		}

		waitForMfaNeededNotBefore(t, idName, beforeRenewal.Add(mfaCheckTimeout))
	})
}

// An identity asked for a code at login stays locked until it gives one, even when the code it
// gave before its last login has not timed out yet: that code belongs to the old session.
func reauthPromptStaysUntilCode(t *testing.T) {
	testutil.RunWithTimeoutOf(t, 90*time.Second, func(t *testing.T) {
		idName := "test_mfa_posture_reauth"
		p := setUpMfaPostureService(t, idName, mfaReauthCheckTimeout)

		triggerReauthChallenge(t, p.identifier, idName)
		require.True(t, statusIdentity(t, p.identifier).MfaNeeded, "MfaNeeded=false for %q after its auth challenge", idName)

		// the timeout check runs every 5s: give it a few runs while the old code still has time left
		time.Sleep(12 * time.Second)
		identity := statusIdentity(t, p.identifier)
		require.True(t, time.Now().Before(p.beforeCode.Add(mfaReauthCheckTimeout)),
			"status read %s after the old code, past its %s timeout: the old code no longer tells the cases apart",
			time.Since(p.beforeCode), mfaReauthCheckTimeout)
		require.True(t, identity.MfaNeeded, "MfaNeeded=false for %q while its login waits for a code", idName)

		// the code unlocks it
		state.zetClient.SkipToNow()
		code := testutil.GenerateTOTP(t, p.secret, time.Now())
		state.zetClient.SubmitMFA(t, p.identifier, code).AssertSuccess()
		state.zetClient.WaitForIdentityEvent(t, "updated", idName).AssertMfaAuthenticated()
	})
}

type mfaPostureService struct {
	identifier string
	secret     string
	// the code verifying the enrollment was taken between these
	beforeCode time.Time
	afterCode  time.Time
}

// setUpMfaPostureService enrolls idName with MFA, returning once the tunneler has its code for
// the service behind the MFA posture check (all from testdata/fixture.json) with the given timeout.
func setUpMfaPostureService(t *testing.T, idName string, checkTimeout time.Duration) mfaPostureService {
	t.Helper()
	beforeCode := time.Now()
	enrollment, secret := testutil.EnrollAndVerifyMFA(t, state.overlay, state.zetClient, idName)
	afterCode := time.Now()
	t.Cleanup(func() {
		state.zetClient.RemoveIdentity(t, enrollment.Identifier)
	})

	for !hasCodeForService(statusIdentity(t, enrollment.Identifier), idName+"_svc", checkTimeout) {
		time.Sleep(500 * time.Millisecond)
	}
	return mfaPostureService{
		identifier: enrollment.Identifier,
		secret:     secret,
		beforeCode: beforeCode,
		afterCode:  afterCode,
	}
}

// waitForMfaNeededNotBefore waits for the identity event that sets MfaNeeded, and fails if it
// comes before the code can have run out (with a second for the code time being whole seconds).
func waitForMfaNeededNotBefore(t *testing.T, idName string, runsOut time.Time) {
	t.Helper()
	for {
		ev := state.zetClient.WaitForIdentityEvent(t, "updated", idName)
		if !ev.Id.MfaNeeded {
			continue
		}
		require.False(t, time.Now().Before(runsOut.Add(-time.Second)),
			"MfaNeeded=true for %q %s before its code runs out", idName, time.Until(runsOut))
		return
	}
}

func statusIdentity(t *testing.T, identifier string) testutil.Identity {
	t.Helper()
	resp := state.zetClient.Status(t)
	resp.AssertSuccess()
	for _, identity := range resp.Data.Identities {
		if identity.Identifier == identifier {
			return identity
		}
	}
	require.FailNow(t, "identity missing from status", "identifier=%s", identifier)
	return testutil.Identity{}
}

// hasCodeForService: the tunneler has the service with its MFA timeout, and a code that has time left
func hasCodeForService(identity testutil.Identity, serviceName string, timeout time.Duration) bool {
	for _, svc := range identity.Services {
		if svc.Name == serviceName && svc.Timeout == int(timeout.Seconds()) && svc.TimeoutRemaining > 0 {
			return true
		}
	}
	return false
}
