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
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/openziti/ziti-tunnel-sdk-c/tests/integration/testutil"
	"github.com/stretchr/testify/require"
)

func TestEnableMFA(t *testing.T) {
	t.Run("acceptsJwtEnrolledIdentity", testEnableMFAAcceptsJwtEnrolledIdentity)
	t.Run("acceptsTotpRequiredAuthPolicy", testEnableMFAAcceptsTotpRequiredAuthPolicy)
}

func TestVerifyMFA(t *testing.T) {
	t.Run("acceptsValidTotp", testVerifyMFAAcceptsValidTotp)
	t.Run("rejectsInvalidTotp", testVerifyMFARejectsInvalidTotp)
}

func TestMFAReauthentication(t *testing.T) {
	t.Run("acceptsValidTotp", testMFAReauthenticationAcceptsValidTotp)
	t.Run("acceptsRecoveryCode", testMFAReauthenticationAcceptsRecoveryCode)
	t.Run("rejectsInvalidTotp", testMFAReauthenticationRejectsInvalidTotp)
}

func TestRemoveMFA(t *testing.T) {
	t.Run("acceptsValidTotp", testRemoveMFAAcceptsValidTotp)
	t.Run("acceptsRecoveryCode", testRemoveMFAAcceptsRecoveryCode)
	t.Run("rejectsInvalidTotp", testRemoveMFARejectsInvalidTotp)
}

func testEnableMFAAcceptsJwtEnrolledIdentity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	enrolled, _ := newEnrolledMFA(t, ctx, testutil.IdentityName(t))

	require.False(t, enrolled.IsVerified, "EnableMFA Data.IsVerified should be false before verify_mfa")
	t.Logf("EnableMFA returned IsVerified=%t (expected false before VerifyMFA)", enrolled.IsVerified)
}

func testEnableMFAAcceptsTotpRequiredAuthPolicy(t *testing.T) {
	t.Skip("Tracking https://github.com/openziti/desktop-edge-win/issues/947 and https://openziti.discourse.group/t/enrolling-mfa-totp-from-zdew-fails/5482 - EnableMFA fails with 'failed to authenticate' for identities bound to TOTP-required auth policies")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	name := testutil.IdentityName(t)
	policy := name + "-policy"
	t.Logf("creating TOTP-required auth policy %q", policy)
	require.NoError(t, overlay.CreateAuthPolicyRequiringTOTP(ctx, policy), "create auth policy")

	t.Logf("minting JWT for %q bound to auth policy %q", name, policy)
	jwt, err := overlay.CreateIdentityJWTWithAuthPolicy(ctx, name, policy)
	require.NoError(t, err, "mint JWT for identity bound to %q", policy)
	require.NotEmpty(t, jwt)

	events, err := zet.DialEvents(ctx)
	require.NoError(t, err, "dial ZET event pipe")
	t.Cleanup(func() { _ = events.Close() })

	client, err := zet.DialIPC(ctx)
	require.NoError(t, err, "dial ZET IPC pipe")
	t.Cleanup(func() { _ = client.Close() })

	identityData := testutil.AddIdentityData{
		IdentityFilename: name,
		JwtContent:       &jwt,
	}
	addResp := testutil.Enroll(t, ctx, client, identityData)
	require.True(t, addResp.Success, "AddIdentity failed: error=%q code=%d", addResp.Error, addResp.Code)
	t.Logf("AddIdentity succeeded for %q", name)

	t.Logf("waiting for identity:added event for %q", name)
	events.WaitFor(t, ctx, "identity", "added", name)
	t.Logf("identity:added event received")

	t.Logf("fetching tunnel status")
	status, err := client.GetTunnelStatus(ctx)
	require.NoError(t, err, "Status after AddIdentity\n%s", zet.Logs())
	entry := status.FindIdentity(name)
	require.NotNil(t, entry, "identity %q not found in Status.Identities", name)
	t.Logf("found %q in status with Identifier=%s", name, entry.Identifier)

	t.Logf("sending EnableMFA for %q", name)
	enrollment, err := client.GetMFAEnrollment(ctx, entry.Identifier)
	require.NoError(t, err, "EnableMFA\n%s", zet.Logs())
	require.NotEmpty(t, enrollment.ProvisioningUrl, "EnableMFA Data.ProvisioningUrl should be non-empty")
	require.NotEmpty(t, enrollment.RecoveryCodes, "EnableMFA Data.RecoveryCodes should be non-empty")
	t.Logf("EnableMFA returned ProvisioningUrl and %d recovery codes", len(enrollment.RecoveryCodes))
}

func testVerifyMFAAcceptsValidTotp(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	name := testutil.IdentityName(t)
	enrolled, _ := newEnrolledMFA(t, ctx, name)

	code, err := generateTotpCode(enrolled.Secret, time.Now())
	require.NoError(t, err, "compute TOTP")

	t.Logf("sending VerifyMFA with valid TOTP for %q", name)
	verifyResp, err := enrolled.Client.VerifyMFA(ctx, enrolled.Identifier, code)
	require.NoError(t, err, "VerifyMFA send\n%s", zet.Logs())
	require.True(t, verifyResp.Success, "VerifyMFA failed: error=%q code=%d\n%s", verifyResp.Error, verifyResp.Code, zet.Logs())
	t.Logf("VerifyMFA succeeded for %q", name)

	t.Logf("fetching tunnel status to confirm MfaEnabled")
	status, err := enrolled.Client.GetTunnelStatus(ctx)
	require.NoError(t, err, "Status after VerifyMFA\n%s", zet.Logs())
	entry := status.FindIdentity(name)
	require.NotNil(t, entry, "identity %q not found in Status after VerifyMFA", name)
	require.True(t, entry.MfaEnabled, "Status.Identities[%q].MfaEnabled should be true after VerifyMFA", name)
	t.Logf("VerifyMFA ID MfaEnabled=%t", entry.MfaEnabled)
}

func testVerifyMFARejectsInvalidTotp(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	name := testutil.IdentityName(t)
	enrolled, _ := newEnrolledMFA(t, ctx, name)

	t.Logf("sending VerifyMFA with invalid TOTP for %q", name)
	verifyResp, err := enrolled.Client.VerifyMFA(ctx, enrolled.Identifier, "000000")
	require.NoError(t, err, "VerifyMFA send\n%s", zet.Logs())
	require.False(t, verifyResp.Success, "VerifyMFA with invalid TOTP should fail but Success=true")
	t.Logf("VerifyMFA correctly rejected invalid TOTP: error=%q code=%d", verifyResp.Error, verifyResp.Code)

	t.Logf("fetching tunnel status to confirm MfaEnabled stayed false")
	status, err := enrolled.Client.GetTunnelStatus(ctx)
	require.NoError(t, err, "Status after VerifyMFA\n%s", zet.Logs())
	entry := status.FindIdentity(name)
	require.NotNil(t, entry, "identity %q not found in Status after VerifyMFA", name)
	require.False(t, entry.MfaEnabled, "Status.Identities[%q].MfaEnabled should remain false after rejected VerifyMFA", name)
	t.Logf("status reports MfaEnabled=%t after rejection", entry.MfaEnabled)
}

func testMFAReauthenticationAcceptsValidTotp(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	name := testutil.IdentityName(t)
	enrolled, events := newEnrolledMFA(t, ctx, name)

	code, err := generateTotpCode(enrolled.Secret, time.Now())
	require.NoError(t, err, "compute TOTP")

	t.Logf("sending VerifyMFA with valid TOTP for %q", name)
	verifyResp, err := enrolled.Client.VerifyMFA(ctx, enrolled.Identifier, code)
	require.NoError(t, err, "VerifyMFA send\n%s", zet.Logs())
	require.True(t, verifyResp.Success, "VerifyMFA failed: error=%q code=%d\n%s", verifyResp.Error, verifyResp.Code, zet.Logs())
	t.Logf("VerifyMFA succeeded for %q", name)

	t.Logf("sending IdentityOnOff(false) for %q to drop the session", name)
	offResp, err := enrolled.Client.IdentityOnOff(ctx, enrolled.Identifier, false)
	require.NoError(t, err, "IdentityOnOff(false) send\n%s", zet.Logs())
	require.True(t, offResp.Success, "IdentityOnOff(false) failed: error=%q code=%d", offResp.Error, offResp.Code)
	t.Logf("IdentityOnOff(false) succeeded")

	t.Logf("sending IdentityOnOff(true) for %q to force re-auth", name)
	onResp, err := enrolled.Client.IdentityOnOff(ctx, enrolled.Identifier, true)
	require.NoError(t, err, "IdentityOnOff(true) send\n%s", zet.Logs())
	require.True(t, onResp.Success, "IdentityOnOff(true) failed: error=%q code=%d", onResp.Error, onResp.Code)
	t.Logf("IdentityOnOff(true) succeeded")

	t.Logf("waiting for mfa:auth_challenge event for %q", name)
	events.WaitFor(t, ctx, "mfa", "auth_challenge", name)
	t.Logf("mfa:auth_challenge event received")

	t.Logf("fetching tunnel status to confirm MfaNeeded")
	status, err := enrolled.Client.GetTunnelStatus(ctx)
	require.NoError(t, err, "Status after auth_challenge\n%s", zet.Logs())
	entry := status.FindIdentity(name)
	require.NotNil(t, entry, "identity %q not found in Status after auth_challenge", name)
	require.True(t, entry.MfaNeeded, "Status.Identities[%q].MfaNeeded should be true after off-then-on cycle", name)
	t.Logf("status reports MfaNeeded=%t after off-then-on cycle", entry.MfaNeeded)

	code, err = generateTotpCode(enrolled.Secret, time.Now())
	require.NoError(t, err, "compute TOTP")

	t.Logf("sending SubmitMFA with valid TOTP for %q", name)
	submitResp, err := enrolled.Client.SubmitMFA(ctx, enrolled.Identifier, code)
	require.NoError(t, err, "SubmitMFA send\n%s", zet.Logs())
	require.True(t, submitResp.Success, "SubmitMFA failed: error=%q code=%d\n%s", submitResp.Error, submitResp.Code, zet.Logs())
	t.Logf("SubmitMFA succeeded for %q", name)

	t.Logf("fetching tunnel status to confirm re-auth cleared MfaNeeded")
	status, err = enrolled.Client.GetTunnelStatus(ctx)
	require.NoError(t, err, "Status after SubmitMFA\n%s", zet.Logs())
	entry = status.FindIdentity(name)
	require.NotNil(t, entry, "identity %q not found in Status after SubmitMFA", name)
	require.False(t, entry.MfaNeeded, "Status.Identities[%q].MfaNeeded should be false after SubmitMFA", name)
	require.True(t, entry.MfaEnabled, "Status.Identities[%q].MfaEnabled should remain true after SubmitMFA", name)
	t.Logf("SubmitMFA ID MfaEnabled=%t MfaNeeded=%t", entry.MfaEnabled, entry.MfaNeeded)
}

func testMFAReauthenticationAcceptsRecoveryCode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	name := testutil.IdentityName(t)
	enrolled, events := newEnrolledMFA(t, ctx, name)

	code, err := generateTotpCode(enrolled.Secret, time.Now())
	require.NoError(t, err, "compute TOTP")

	t.Logf("sending VerifyMFA with valid TOTP for %q", name)
	verifyResp, err := enrolled.Client.VerifyMFA(ctx, enrolled.Identifier, code)
	require.NoError(t, err, "VerifyMFA send\n%s", zet.Logs())
	require.True(t, verifyResp.Success, "VerifyMFA failed: error=%q code=%d\n%s", verifyResp.Error, verifyResp.Code, zet.Logs())
	t.Logf("VerifyMFA succeeded for %q", name)

	t.Logf("sending IdentityOnOff(false) for %q to drop the session", name)
	offResp, err := enrolled.Client.IdentityOnOff(ctx, enrolled.Identifier, false)
	require.NoError(t, err, "IdentityOnOff(false) send\n%s", zet.Logs())
	require.True(t, offResp.Success, "IdentityOnOff(false) failed: error=%q code=%d", offResp.Error, offResp.Code)
	t.Logf("IdentityOnOff(false) succeeded")

	t.Logf("sending IdentityOnOff(true) for %q to force re-auth", name)
	onResp, err := enrolled.Client.IdentityOnOff(ctx, enrolled.Identifier, true)
	require.NoError(t, err, "IdentityOnOff(true) send\n%s", zet.Logs())
	require.True(t, onResp.Success, "IdentityOnOff(true) failed: error=%q code=%d", onResp.Error, onResp.Code)
	t.Logf("IdentityOnOff(true) succeeded")

	t.Logf("waiting for mfa:auth_challenge event for %q", name)
	events.WaitFor(t, ctx, "mfa", "auth_challenge", name)
	t.Logf("mfa:auth_challenge event received")

	t.Logf("fetching tunnel status to confirm MfaNeeded")
	status, err := enrolled.Client.GetTunnelStatus(ctx)
	require.NoError(t, err, "Status after auth_challenge\n%s", zet.Logs())
	entry := status.FindIdentity(name)
	require.NotNil(t, entry, "identity %q not found in Status after auth_challenge", name)
	require.True(t, entry.MfaNeeded, "Status.Identities[%q].MfaNeeded should be true after off-then-on cycle", name)
	t.Logf("status reports MfaNeeded=%t after off-then-on cycle", entry.MfaNeeded)

	t.Logf("sending SubmitMFA with recovery code for %q", name)
	submitResp, err := enrolled.Client.SubmitMFA(ctx, enrolled.Identifier, enrolled.RecoveryCodes[0])
	require.NoError(t, err, "SubmitMFA send\n%s", zet.Logs())
	require.True(t, submitResp.Success, "SubmitMFA failed: error=%q code=%d\n%s", submitResp.Error, submitResp.Code, zet.Logs())
	t.Logf("SubmitMFA with recovery code succeeded for %q", name)

	t.Logf("fetching tunnel status to confirm re-auth cleared MfaNeeded")
	status, err = enrolled.Client.GetTunnelStatus(ctx)
	require.NoError(t, err, "Status after SubmitMFA\n%s", zet.Logs())
	entry = status.FindIdentity(name)
	require.NotNil(t, entry, "identity %q not found in Status after SubmitMFA", name)
	require.False(t, entry.MfaNeeded, "Status.Identities[%q].MfaNeeded should be false after SubmitMFA", name)
	require.True(t, entry.MfaEnabled, "Status.Identities[%q].MfaEnabled should remain true after SubmitMFA", name)
	t.Logf("SubmitMFA ID MfaEnabled=%t MfaNeeded=%t", entry.MfaEnabled, entry.MfaNeeded)
}

func testMFAReauthenticationRejectsInvalidTotp(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	name := testutil.IdentityName(t)
	enrolled, events := newEnrolledMFA(t, ctx, name)

	code, err := generateTotpCode(enrolled.Secret, time.Now())
	require.NoError(t, err, "compute TOTP")

	t.Logf("sending VerifyMFA with valid TOTP for %q", name)
	verifyResp, err := enrolled.Client.VerifyMFA(ctx, enrolled.Identifier, code)
	require.NoError(t, err, "VerifyMFA send\n%s", zet.Logs())
	require.True(t, verifyResp.Success, "VerifyMFA failed: error=%q code=%d\n%s", verifyResp.Error, verifyResp.Code, zet.Logs())
	t.Logf("VerifyMFA succeeded for %q", name)

	t.Logf("sending IdentityOnOff(false) for %q to drop the session", name)
	offResp, err := enrolled.Client.IdentityOnOff(ctx, enrolled.Identifier, false)
	require.NoError(t, err, "IdentityOnOff(false) send\n%s", zet.Logs())
	require.True(t, offResp.Success, "IdentityOnOff(false) failed: error=%q code=%d", offResp.Error, offResp.Code)
	t.Logf("IdentityOnOff(false) succeeded")

	t.Logf("sending IdentityOnOff(true) for %q to force re-auth", name)
	onResp, err := enrolled.Client.IdentityOnOff(ctx, enrolled.Identifier, true)
	require.NoError(t, err, "IdentityOnOff(true) send\n%s", zet.Logs())
	require.True(t, onResp.Success, "IdentityOnOff(true) failed: error=%q code=%d", onResp.Error, onResp.Code)
	t.Logf("IdentityOnOff(true) succeeded")

	t.Logf("waiting for mfa:auth_challenge event for %q", name)
	events.WaitFor(t, ctx, "mfa", "auth_challenge", name)
	t.Logf("mfa:auth_challenge event received")

	t.Logf("sending SubmitMFA with invalid TOTP for %q", name)
	submitResp, err := enrolled.Client.SubmitMFA(ctx, enrolled.Identifier, "000000")
	require.NoError(t, err, "SubmitMFA send\n%s", zet.Logs())
	require.False(t, submitResp.Success, "SubmitMFA with invalid TOTP should fail but Success=true")
	t.Logf("SubmitMFA correctly rejected invalid TOTP: error=%q code=%d", submitResp.Error, submitResp.Code)

	t.Logf("fetching tunnel status to confirm MFA state unchanged")
	status, err := enrolled.Client.GetTunnelStatus(ctx)
	require.NoError(t, err, "Status after rejected SubmitMFA\n%s", zet.Logs())
	entry := status.FindIdentity(name)
	require.NotNil(t, entry, "identity %q not found in Status after rejected SubmitMFA", name)
	require.True(t, entry.MfaNeeded, "Status.Identities[%q].MfaNeeded should remain true after rejected SubmitMFA", name)
	require.True(t, entry.MfaEnabled, "Status.Identities[%q].MfaEnabled should remain true after rejected SubmitMFA", name)
	t.Logf("status reports MfaNeeded=%t MfaEnabled=%t after rejection", entry.MfaNeeded, entry.MfaEnabled)
}

func testRemoveMFAAcceptsValidTotp(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	name := testutil.IdentityName(t)
	enrolled, _ := newEnrolledMFA(t, ctx, name)

	code, err := generateTotpCode(enrolled.Secret, time.Now())
	require.NoError(t, err, "compute TOTP")

	t.Logf("sending VerifyMFA with valid TOTP for %q", name)
	verifyResp, err := enrolled.Client.VerifyMFA(ctx, enrolled.Identifier, code)
	require.NoError(t, err, "VerifyMFA send\n%s", zet.Logs())
	require.True(t, verifyResp.Success, "VerifyMFA failed: error=%q code=%d\n%s", verifyResp.Error, verifyResp.Code, zet.Logs())
	t.Logf("VerifyMFA succeeded for %q", name)

	code, err = generateTotpCode(enrolled.Secret, time.Now())
	require.NoError(t, err, "compute TOTP")

	t.Logf("sending RemoveMFA with valid TOTP for %q", name)
	removeResp, err := enrolled.Client.RemoveMFA(ctx, enrolled.Identifier, code)
	require.NoError(t, err, "RemoveMFA send\n%s", zet.Logs())
	require.True(t, removeResp.Success, "RemoveMFA failed: error=%q code=%d\n%s", removeResp.Error, removeResp.Code, zet.Logs())
	t.Logf("RemoveMFA succeeded for %q", name)

	t.Logf("fetching tunnel status to confirm MfaEnabled cleared")
	status, err := enrolled.Client.GetTunnelStatus(ctx)
	require.NoError(t, err, "Status after RemoveMFA\n%s", zet.Logs())
	entry := status.FindIdentity(name)
	require.NotNil(t, entry, "identity %q not found in Status after RemoveMFA", name)
	require.False(t, entry.MfaEnabled, "Status.Identities[%q].MfaEnabled should be false after RemoveMFA", name)
	t.Logf("status reports MfaEnabled=%t after RemoveMFA with TOTP", entry.MfaEnabled)
}

func testRemoveMFAAcceptsRecoveryCode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	name := testutil.IdentityName(t)
	enrolled, _ := newEnrolledMFA(t, ctx, name)

	code, err := generateTotpCode(enrolled.Secret, time.Now())
	require.NoError(t, err, "compute TOTP")

	t.Logf("sending VerifyMFA with valid TOTP for %q", name)
	verifyResp, err := enrolled.Client.VerifyMFA(ctx, enrolled.Identifier, code)
	require.NoError(t, err, "VerifyMFA send\n%s", zet.Logs())
	require.True(t, verifyResp.Success, "VerifyMFA failed: error=%q code=%d\n%s", verifyResp.Error, verifyResp.Code, zet.Logs())
	t.Logf("VerifyMFA succeeded for %q", name)

	t.Logf("sending RemoveMFA with recovery code for %q", name)
	removeResp, err := enrolled.Client.RemoveMFA(ctx, enrolled.Identifier, enrolled.RecoveryCodes[0])
	require.NoError(t, err, "RemoveMFA send\n%s", zet.Logs())
	require.True(t, removeResp.Success, "RemoveMFA failed: error=%q code=%d\n%s", removeResp.Error, removeResp.Code, zet.Logs())
	t.Logf("RemoveMFA with recovery code succeeded for %q", name)

	t.Logf("fetching tunnel status to confirm MfaEnabled cleared")
	status, err := enrolled.Client.GetTunnelStatus(ctx)
	require.NoError(t, err, "Status after RemoveMFA\n%s", zet.Logs())
	entry := status.FindIdentity(name)
	require.NotNil(t, entry, "identity %q not found in Status after RemoveMFA", name)
	require.False(t, entry.MfaEnabled, "Status.Identities[%q].MfaEnabled should be false after RemoveMFA", name)
	t.Logf("status reports MfaEnabled=%t after RemoveMFA with recovery code", entry.MfaEnabled)
}

func testRemoveMFARejectsInvalidTotp(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	name := testutil.IdentityName(t)
	enrolled, _ := newEnrolledMFA(t, ctx, name)

	code, err := generateTotpCode(enrolled.Secret, time.Now())
	require.NoError(t, err, "compute TOTP")

	t.Logf("sending VerifyMFA with valid TOTP for %q", name)
	verifyResp, err := enrolled.Client.VerifyMFA(ctx, enrolled.Identifier, code)
	require.NoError(t, err, "VerifyMFA send\n%s", zet.Logs())
	require.True(t, verifyResp.Success, "VerifyMFA failed: error=%q code=%d\n%s", verifyResp.Error, verifyResp.Code, zet.Logs())
	t.Logf("VerifyMFA succeeded for %q", name)

	t.Logf("sending RemoveMFA with invalid TOTP for %q", name)
	removeResp, err := enrolled.Client.RemoveMFA(ctx, enrolled.Identifier, "000000")
	require.NoError(t, err, "RemoveMFA send\n%s", zet.Logs())
	require.False(t, removeResp.Success, "RemoveMFA with invalid TOTP should fail but Success=true")
	t.Logf("RemoveMFA correctly rejected invalid TOTP: error=%q code=%d", removeResp.Error, removeResp.Code)

	t.Logf("fetching tunnel status to confirm MfaEnabled unchanged")
	status, err := enrolled.Client.GetTunnelStatus(ctx)
	require.NoError(t, err, "Status after rejected RemoveMFA\n%s", zet.Logs())
	entry := status.FindIdentity(name)
	require.NotNil(t, entry, "identity %q not found in Status after rejected RemoveMFA", name)
	require.True(t, entry.MfaEnabled, "Status.Identities[%q].MfaEnabled should remain true after rejected RemoveMFA", name)
	t.Logf("status reports MfaEnabled=%t after rejected RemoveMFA", entry.MfaEnabled)
}

type enrolledMFA struct {
	Client        *testutil.IPCClient
	Identifier    string
	IsVerified    bool
	RecoveryCodes []string
	Secret        string
}

func newEnrolledMFA(t *testing.T, ctx context.Context, name string) (*enrolledMFA, *testutil.EventClient) {
	t.Helper()

	t.Logf("minting JWT for %q", name)
	jwt, err := overlay.CreateIdentityJWT(ctx, name)
	require.NoError(t, err, "mint JWT")
	require.NotEmpty(t, jwt)

	events, err := zet.DialEvents(ctx)
	require.NoError(t, err, "dial ZET event pipe")
	t.Cleanup(func() { _ = events.Close() })

	client, err := zet.DialIPC(ctx)
	require.NoError(t, err, "dial ZET IPC pipe")
	t.Cleanup(func() { _ = client.Close() })

	identityData := testutil.AddIdentityData{
		IdentityFilename: name,
		JwtContent:       &jwt,
	}
	addResp := testutil.Enroll(t, ctx, client, identityData)
	require.True(t, addResp.Success, "AddIdentity failed: error=%q code=%d", addResp.Error, addResp.Code)

	t.Logf("waiting for controller:connected event for %q", name)
	events.WaitFor(t, ctx, "controller", "connected", name)
	t.Logf("controller:connected event received")

	t.Logf("fetching tunnel status")
	status, err := client.GetTunnelStatus(ctx)
	require.NoError(t, err, "Status after AddIdentity\n%s", zet.Logs())
	entry := status.FindIdentity(name)
	require.NotNil(t, entry, "identity %q not found in Status.Identities", name)
	identifier := entry.Identifier
	t.Logf("found %q in status with Identifier=%s", name, identifier)

	t.Logf("sending EnableMFA for %q", name)
	enrollment, err := client.GetMFAEnrollment(ctx, identifier)
	require.NoError(t, err, "EnableMFA\n%s", zet.Logs())
	require.NotEmpty(t, enrollment.ProvisioningUrl, "EnableMFA Data.ProvisioningUrl should be non-empty")
	require.NotEmpty(t, enrollment.RecoveryCodes, "EnableMFA Data.RecoveryCodes should be non-empty")
	t.Logf("EnableMFA returned ProvisioningUrl and %d recovery codes", len(enrollment.RecoveryCodes))

	parsed, err := url.Parse(enrollment.ProvisioningUrl)
	require.NoError(t, err, "parse provisioning url %q", enrollment.ProvisioningUrl)
	secret := parsed.Query().Get("secret")
	require.NotEmpty(t, secret, "provisioning url missing secret param: %q", enrollment.ProvisioningUrl)

	return &enrolledMFA{
		Client:        client,
		Identifier:    identifier,
		IsVerified:    enrollment.IsVerified,
		RecoveryCodes: enrollment.RecoveryCodes,
		Secret:        secret,
	}, events
}

func generateTotpCode(secret string, at time.Time) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimRight(secret, "=")))
	if err != nil {
		return "", fmt.Errorf("base32 decode secret: %w", err)
	}
	counter := uint64(at.Unix() / 30)
	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", code%1_000_000), nil
}
