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
	t.Run("withJwtEnrolledIdentity", testEnableMFAWithJwtEnrolledIdentity)
	t.Run("withTotpRequiredAuthPolicy", testEnableMFAWithTotpRequiredAuthPolicy)
}

func TestVerifyMFA(t *testing.T) {
	t.Run("withValidTotp", testVerifyMFAWithValidTotp)
}

func TestMFAReauthentication(t *testing.T) {
	t.Run("afterIdentityToggle", testMFAReauthenticationAfterIdentityToggle)
}

func TestRemoveMFA(t *testing.T) {
	t.Run("withValidTotp", testRemoveMFAWithValidTotp)
	t.Run("withRecoveryCode", testRemoveMFAWithRecoveryCode)
}

func testEnableMFAWithJwtEnrolledIdentity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	name := identityNameFor(t)
	jwt, err := overlay.CreateIdentityJWT(ctx, name)
	require.NoError(t, err, "mint JWT")
	require.NotEmpty(t, jwt)
	t.Logf("JWT minted for identity %q (%d bytes)", name, len(jwt))

	events, err := testutil.DialEvents(ctx)
	require.NoError(t, err, "dial ZET event pipe")
	t.Cleanup(func() { _ = events.Close() })

	client, err := testutil.DialIPC(ctx)
	require.NoError(t, err, "dial ZET IPC pipe")
	t.Cleanup(func() { _ = client.Close() })

	identityData := testutil.AddIdentityData{
		IdentityFilename: name,
		JwtContent:       &jwt,
	}
	addResp, err := client.AddIdentity(ctx, identityData)
	require.NoError(t, err, "AddIdentity send\n%s", zet.Logs())
	require.True(t, addResp.Success, "AddIdentity failed: error=%q code=%d", addResp.Error, addResp.Code)

	events.WaitFor(t, ctx, "controller", "connected", name)

	status, err := client.GetTunnelStatus(ctx)
	require.NoError(t, err, "Status after AddIdentity\n%s", zet.Logs())
	entry := status.FindIdentity(name)
	require.NotNil(t, entry, "identity %q not found in Status.Identities", name)

	mfa, err := client.GetMFAEnrollment(ctx, entry.Identifier)
	require.NoError(t, err, "EnableMFA\n%s", zet.Logs())
	require.NotEmpty(t, mfa.ProvisioningUrl, "EnableMFA Data.ProvisioningUrl should be non-empty")
	require.NotEmpty(t, mfa.RecoveryCodes, "EnableMFA Data.RecoveryCodes should be non-empty")
	require.False(t, mfa.IsVerified, "EnableMFA Data.IsVerified should be false before verify_mfa")
	t.Logf("EnableMFA succeeded: provisioning_url=%q recovery_codes=%d", mfa.ProvisioningUrl, len(mfa.RecoveryCodes))
}

func testEnableMFAWithTotpRequiredAuthPolicy(t *testing.T) {
	t.Skip("Tracking https://github.com/openziti/desktop-edge-win/issues/947 and https://openziti.discourse.group/t/enrolling-mfa-totp-from-zdew-fails/5482 - EnableMFA fails with 'failed to authenticate' for identities bound to TOTP-required auth policies")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	name := identityNameFor(t)
	policy := name + "-policy"
	require.NoError(t, overlay.CreateAuthPolicyRequiringTOTP(ctx, policy), "create auth policy")
	t.Logf("auth policy %q created (--secondary-req-totp)", policy)

	jwt, err := overlay.CreateIdentityJWTWithAuthPolicy(ctx, name, policy)
	require.NoError(t, err, "mint JWT for identity bound to %q", policy)
	require.NotEmpty(t, jwt)
	t.Logf("JWT minted for identity %q bound to policy %q (%d bytes)", name, policy, len(jwt))

	events, err := testutil.DialEvents(ctx)
	require.NoError(t, err, "dial ZET event pipe")
	t.Cleanup(func() { _ = events.Close() })

	client, err := testutil.DialIPC(ctx)
	require.NoError(t, err, "dial ZET IPC pipe")
	t.Cleanup(func() { _ = client.Close() })

	identityData := testutil.AddIdentityData{
		IdentityFilename: name,
		JwtContent:       &jwt,
	}
	addResp, err := client.AddIdentity(ctx, identityData)
	require.NoError(t, err, "AddIdentity send\n%s", zet.Logs())
	require.True(t, addResp.Success, "AddIdentity failed: error=%q code=%d", addResp.Error, addResp.Code)

	events.WaitFor(t, ctx, "identity", "added", name)

	status, err := client.GetTunnelStatus(ctx)
	require.NoError(t, err, "Status after AddIdentity\n%s", zet.Logs())
	entry := status.FindIdentity(name)
	require.NotNil(t, entry, "identity %q not found in Status.Identities", name)

	mfa, err := client.GetMFAEnrollment(ctx, entry.Identifier)
	require.NoError(t, err, "EnableMFA\n%s", zet.Logs())
	require.NotEmpty(t, mfa.ProvisioningUrl, "EnableMFA Data.ProvisioningUrl should be non-empty")
	require.NotEmpty(t, mfa.RecoveryCodes, "EnableMFA Data.RecoveryCodes should be non-empty")
	t.Logf("EnableMFA succeeded for TOTP-required identity: provisioning_url=%q", mfa.ProvisioningUrl)
}

func testVerifyMFAWithValidTotp(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	name := identityNameFor(t)
	jwt, err := overlay.CreateIdentityJWT(ctx, name)
	require.NoError(t, err, "mint JWT")
	require.NotEmpty(t, jwt)
	t.Logf("JWT minted for identity %q (%d bytes)", name, len(jwt))

	events, err := testutil.DialEvents(ctx)
	require.NoError(t, err, "dial ZET event pipe")
	t.Cleanup(func() { _ = events.Close() })

	client, err := testutil.DialIPC(ctx)
	require.NoError(t, err, "dial ZET IPC pipe")
	t.Cleanup(func() { _ = client.Close() })

	identityData := testutil.AddIdentityData{
		IdentityFilename: name,
		JwtContent:       &jwt,
	}
	addResp, err := client.AddIdentity(ctx, identityData)
	require.NoError(t, err, "AddIdentity send\n%s", zet.Logs())
	require.True(t, addResp.Success, "AddIdentity failed: error=%q code=%d", addResp.Error, addResp.Code)

	events.WaitFor(t, ctx, "controller", "connected", name)

	status, err := client.GetTunnelStatus(ctx)
	require.NoError(t, err, "Status after AddIdentity\n%s", zet.Logs())
	entry := status.FindIdentity(name)
	require.NotNil(t, entry, "identity %q not found in Status.Identities", name)

	mfa, err := client.GetMFAEnrollment(ctx, entry.Identifier)
	require.NoError(t, err, "EnableMFA\n%s", zet.Logs())
	require.NotEmpty(t, mfa.ProvisioningUrl, "EnableMFA Data.ProvisioningUrl should be non-empty")

	parsed, err := url.Parse(mfa.ProvisioningUrl)
	require.NoError(t, err, "parse provisioning url %q", mfa.ProvisioningUrl)
	secret := parsed.Query().Get("secret")
	require.NotEmpty(t, secret, "provisioning url missing secret param: %q", mfa.ProvisioningUrl)

	code, err := generateTotpCode(secret, time.Now())
	require.NoError(t, err, "compute TOTP code")
	t.Logf("computed TOTP code from secret (%d chars)", len(secret))

	verifyResp, err := client.VerifyMFA(ctx, entry.Identifier, code)
	require.NoError(t, err, "VerifyMFA send\n%s", zet.Logs())
	require.True(t, verifyResp.Success, "VerifyMFA failed: error=%q code=%d\n%s", verifyResp.Error, verifyResp.Code, zet.Logs())
	t.Logf("VerifyMFA succeeded: code=%d", verifyResp.Code)

	status, err = client.GetTunnelStatus(ctx)
	require.NoError(t, err, "Status after VerifyMFA\n%s", zet.Logs())
	entry = status.FindIdentity(name)
	require.NotNil(t, entry, "identity %q not found in Status after VerifyMFA", name)
	require.True(t, entry.MfaEnabled, "Status.Identities[%q].MfaEnabled should be true after VerifyMFA", name)
	t.Logf("VerifyMFA ID MfaEnabled=%t", entry.MfaEnabled)
}

func testMFAReauthenticationAfterIdentityToggle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	name := identityNameFor(t)
	jwt, err := overlay.CreateIdentityJWT(ctx, name)
	require.NoError(t, err, "mint JWT")
	require.NotEmpty(t, jwt)
	t.Logf("JWT minted for identity %q (%d bytes)", name, len(jwt))

	events, err := testutil.DialEvents(ctx)
	require.NoError(t, err, "dial ZET event pipe")
	t.Cleanup(func() { _ = events.Close() })

	client, err := testutil.DialIPC(ctx)
	require.NoError(t, err, "dial ZET IPC pipe")
	t.Cleanup(func() { _ = client.Close() })

	identityData := testutil.AddIdentityData{
		IdentityFilename: name,
		JwtContent:       &jwt,
	}
	addResp, err := client.AddIdentity(ctx, identityData)
	require.NoError(t, err, "AddIdentity send\n%s", zet.Logs())
	require.True(t, addResp.Success, "AddIdentity failed: error=%q code=%d", addResp.Error, addResp.Code)

	events.WaitFor(t, ctx, "controller", "connected", name)

	status, err := client.GetTunnelStatus(ctx)
	require.NoError(t, err, "Status after AddIdentity\n%s", zet.Logs())
	entry := status.FindIdentity(name)
	require.NotNil(t, entry, "identity %q not found in Status.Identities", name)

	mfa, err := client.GetMFAEnrollment(ctx, entry.Identifier)
	require.NoError(t, err, "EnableMFA\n%s", zet.Logs())
	require.NotEmpty(t, mfa.ProvisioningUrl, "EnableMFA Data.ProvisioningUrl should be non-empty")

	parsed, err := url.Parse(mfa.ProvisioningUrl)
	require.NoError(t, err, "parse provisioning url %q", mfa.ProvisioningUrl)
	secret := parsed.Query().Get("secret")
	require.NotEmpty(t, secret, "provisioning url missing secret param: %q", mfa.ProvisioningUrl)

	verifyCode, err := generateTotpCode(secret, time.Now())
	require.NoError(t, err, "compute TOTP code for verify")

	verifyResp, err := client.VerifyMFA(ctx, entry.Identifier, verifyCode)
	require.NoError(t, err, "VerifyMFA send\n%s", zet.Logs())
	require.True(t, verifyResp.Success, "VerifyMFA failed: error=%q code=%d\n%s", verifyResp.Error, verifyResp.Code, zet.Logs())
	t.Logf("VerifyMFA succeeded")

	offResp, err := client.IdentityOnOff(ctx, entry.Identifier, false)
	require.NoError(t, err, "IdentityOnOff(false) send\n%s", zet.Logs())
	require.True(t, offResp.Success, "IdentityOnOff(false) failed: error=%q code=%d", offResp.Error, offResp.Code)

	onResp, err := client.IdentityOnOff(ctx, entry.Identifier, true)
	require.NoError(t, err, "IdentityOnOff(true) send\n%s", zet.Logs())
	require.True(t, onResp.Success, "IdentityOnOff(true) failed: error=%q code=%d", onResp.Error, onResp.Code)

	events.WaitFor(t, ctx, "mfa", "auth_challenge", name)

	status, err = client.GetTunnelStatus(ctx)
	require.NoError(t, err, "Status after auth_challenge\n%s", zet.Logs())
	entry = status.FindIdentity(name)
	require.NotNil(t, entry, "identity %q not found in Status after auth_challenge", name)
	require.True(t, entry.MfaNeeded, "Status.Identities[%q].MfaNeeded should be true after off→on cycle", name)

	submitResp, err := client.SubmitMFA(ctx, entry.Identifier, verifyCode)
	require.NoError(t, err, "SubmitMFA send\n%s", zet.Logs())
	require.True(t, submitResp.Success, "SubmitMFA failed: error=%q code=%d\n%s", submitResp.Error, submitResp.Code, zet.Logs())
	t.Logf("SubmitMFA succeeded: code=%d", submitResp.Code)

	status, err = client.GetTunnelStatus(ctx)
	require.NoError(t, err, "Status after SubmitMFA\n%s", zet.Logs())
	entry = status.FindIdentity(name)
	require.NotNil(t, entry, "identity %q not found in Status after SubmitMFA", name)
	require.False(t, entry.MfaNeeded, "Status.Identities[%q].MfaNeeded should be false after SubmitMFA", name)
	require.True(t, entry.MfaEnabled, "Status.Identities[%q].MfaEnabled should remain true after SubmitMFA", name)
	t.Logf("SubmitMFA ID MfaEnabled=%t MfaNeeded=%t", entry.MfaEnabled, entry.MfaNeeded)
}

func testRemoveMFAWithValidTotp(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	name := identityNameFor(t)
	jwt, err := overlay.CreateIdentityJWT(ctx, name)
	require.NoError(t, err, "mint JWT")
	require.NotEmpty(t, jwt)
	t.Logf("JWT minted for identity %q (%d bytes)", name, len(jwt))

	events, err := testutil.DialEvents(ctx)
	require.NoError(t, err, "dial ZET event pipe")
	t.Cleanup(func() { _ = events.Close() })

	client, err := testutil.DialIPC(ctx)
	require.NoError(t, err, "dial ZET IPC pipe")
	t.Cleanup(func() { _ = client.Close() })

	identityData := testutil.AddIdentityData{
		IdentityFilename: name,
		JwtContent:       &jwt,
	}
	addResp, err := client.AddIdentity(ctx, identityData)
	require.NoError(t, err, "AddIdentity send\n%s", zet.Logs())
	require.True(t, addResp.Success, "AddIdentity failed: error=%q code=%d", addResp.Error, addResp.Code)

	events.WaitFor(t, ctx, "controller", "connected", name)

	status, err := client.GetTunnelStatus(ctx)
	require.NoError(t, err, "Status send\n%s", zet.Logs())
	entry := status.FindIdentity(name)
	require.NotNil(t, entry, "identity %q not found in Status.Identities", name)

	mfa, err := client.GetMFAEnrollment(ctx, entry.Identifier)
	require.NoError(t, err, "EnableMFA\n%s", zet.Logs())
	require.NotEmpty(t, mfa.ProvisioningUrl, "EnableMFA Data.ProvisioningUrl should be non-empty")

	parsed, err := url.Parse(mfa.ProvisioningUrl)
	require.NoError(t, err, "parse provisioning url %q", mfa.ProvisioningUrl)
	secret := parsed.Query().Get("secret")
	require.NotEmpty(t, secret, "provisioning url missing secret param: %q", mfa.ProvisioningUrl)

	verifyCode, err := generateTotpCode(secret, time.Now())
	require.NoError(t, err, "compute TOTP code for verify")

	verifyResp, err := client.VerifyMFA(ctx, entry.Identifier, verifyCode)
	require.NoError(t, err, "VerifyMFA send\n%s", zet.Logs())
	require.True(t, verifyResp.Success, "VerifyMFA failed: error=%q code=%d\n%s", verifyResp.Error, verifyResp.Code, zet.Logs())
	t.Logf("VerifyMFA succeeded")

	// TOTP codes are single-use within their 30s step; sleep into the next step before computing the remove code.
	nextStep := time.Unix((time.Now().Unix()/30+1)*30, 0)
	wait := time.Until(nextStep) + 100*time.Millisecond
	t.Logf("waiting %s for next TOTP step before RemoveMFA", wait)
	time.Sleep(wait)

	removeCode, err := generateTotpCode(secret, time.Now())
	require.NoError(t, err, "compute TOTP code for remove")
	require.NotEqual(t, verifyCode, removeCode, "remove TOTP should be from a different step than verify TOTP")

	removeResp, err := client.RemoveMFA(ctx, entry.Identifier, removeCode)
	require.NoError(t, err, "RemoveMFA send\n%s", zet.Logs())
	require.True(t, removeResp.Success, "RemoveMFA failed: error=%q code=%d\n%s", removeResp.Error, removeResp.Code, zet.Logs())
	t.Logf("RemoveMFA succeeded: code=%d", removeResp.Code)

	status, err = client.GetTunnelStatus(ctx)
	require.NoError(t, err, "Status after RemoveMFA\n%s", zet.Logs())
	entry = status.FindIdentity(name)
	require.NotNil(t, entry, "identity %q not found in Status after RemoveMFA", name)
	require.False(t, entry.MfaEnabled, "Status.Identities[%q].MfaEnabled should be false after RemoveMFA", name)
	t.Logf("RemoveMFA ID with TOTP MfaEnabled=%t", entry.MfaEnabled)
}

func testRemoveMFAWithRecoveryCode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	name := identityNameFor(t)
	jwt, err := overlay.CreateIdentityJWT(ctx, name)
	require.NoError(t, err, "mint JWT")
	require.NotEmpty(t, jwt)
	t.Logf("JWT minted for identity %q (%d bytes)", name, len(jwt))

	events, err := testutil.DialEvents(ctx)
	require.NoError(t, err, "dial ZET event pipe")
	t.Cleanup(func() { _ = events.Close() })

	client, err := testutil.DialIPC(ctx)
	require.NoError(t, err, "dial ZET IPC pipe")
	t.Cleanup(func() { _ = client.Close() })

	identityData := testutil.AddIdentityData{
		IdentityFilename: name,
		JwtContent:       &jwt,
	}
	addResp, err := client.AddIdentity(ctx, identityData)
	require.NoError(t, err, "AddIdentity send\n%s", zet.Logs())
	require.True(t, addResp.Success, "AddIdentity failed: error=%q code=%d", addResp.Error, addResp.Code)

	events.WaitFor(t, ctx, "controller", "connected", name)

	status, err := client.GetTunnelStatus(ctx)
	require.NoError(t, err, "Status send\n%s", zet.Logs())
	entry := status.FindIdentity(name)
	require.NotNil(t, entry, "identity %q not found in Status.Identities", name)

	mfa, err := client.GetMFAEnrollment(ctx, entry.Identifier)
	require.NoError(t, err, "EnableMFA\n%s", zet.Logs())
	require.NotEmpty(t, mfa.ProvisioningUrl, "EnableMFA Data.ProvisioningUrl should be non-empty")
	require.NotEmpty(t, mfa.RecoveryCodes, "EnableMFA Data.RecoveryCodes should be non-empty")

	parsed, err := url.Parse(mfa.ProvisioningUrl)
	require.NoError(t, err, "parse provisioning url %q", mfa.ProvisioningUrl)
	secret := parsed.Query().Get("secret")
	require.NotEmpty(t, secret, "provisioning url missing secret param: %q", mfa.ProvisioningUrl)

	verifyCode, err := generateTotpCode(secret, time.Now())
	require.NoError(t, err, "compute TOTP code for verify")

	verifyResp, err := client.VerifyMFA(ctx, entry.Identifier, verifyCode)
	require.NoError(t, err, "VerifyMFA send\n%s", zet.Logs())
	require.True(t, verifyResp.Success, "VerifyMFA failed: error=%q code=%d\n%s", verifyResp.Error, verifyResp.Code, zet.Logs())
	t.Logf("VerifyMFA succeeded")

	removeResp, err := client.RemoveMFA(ctx, entry.Identifier, mfa.RecoveryCodes[0])
	require.NoError(t, err, "RemoveMFA send\n%s", zet.Logs())
	require.True(t, removeResp.Success, "RemoveMFA failed: error=%q code=%d\n%s", removeResp.Error, removeResp.Code, zet.Logs())
	t.Logf("RemoveMFA succeeded with recovery code: code=%d", removeResp.Code)

	status, err = client.GetTunnelStatus(ctx)
	require.NoError(t, err, "Status after RemoveMFA\n%s", zet.Logs())
	entry = status.FindIdentity(name)
	require.NotNil(t, entry, "identity %q not found in Status after RemoveMFA", name)
	require.False(t, entry.MfaEnabled, "Status.Identities[%q].MfaEnabled should be false after RemoveMFA", name)
	t.Logf("RemoveMFA ID with recovery code MfaEnabled=%t", entry.MfaEnabled)
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
