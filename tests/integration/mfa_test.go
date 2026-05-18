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

	t.Logf("creating JWT for %q bound to auth policy %q", name, policy)
	jwt, err := overlay.CreateIdentityJWTWithAuthPolicy(ctx, name, policy)
	require.NoError(t, err, "failed to create JWT for identity bound to %q", policy)
	require.NotEmpty(t, jwt)

	events := testutil.SubscribeEvents(t, ctx, zet)
	client := testutil.OpenCommandPipe(t, ctx, zet)

	identityData := testutil.AddIdentityData{
		IdentityFilename: name,
		JwtContent:       &jwt,
	}
	addResp := testutil.Enroll(t, ctx, client, identityData)
	require.True(t, addResp.Success, "AddIdentity failed: error=%q code=%d", addResp.Error, addResp.Code)

	added := events.WaitFor(t, ctx, "identity", "added", name)
	require.NotEmpty(t, added.Id.Identifier, "identity:added Identifier empty")

	t.Logf("sending EnableMFA for %q", name)
	enrollment, err := client.GetMFAEnrollment(ctx, added.Id.Identifier)
	require.NoError(t, err, "failed to send EnableMFA\n%s", zet.Logs())
	require.NotEmpty(t, enrollment.ProvisioningUrl, "EnableMFA Data.ProvisioningUrl should be non-empty")
	require.NotEmpty(t, enrollment.RecoveryCodes, "EnableMFA Data.RecoveryCodes should be non-empty")
	t.Logf("EnableMFA returned ProvisioningUrl and %d recovery codes", len(enrollment.RecoveryCodes))
}

func testVerifyMFAAcceptsValidTotp(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	name := testutil.IdentityName(t)
	enrolled, events := newEnrolledMFA(t, ctx, name)

	code, err := generateTotpCode(enrolled.Secret, time.Now())
	require.NoError(t, err, "failed to compute TOTP")

	t.Logf("sending VerifyMFA with valid TOTP for %q", name)
	verifyResp, err := enrolled.Client.VerifyMFA(ctx, enrolled.Identifier, code)
	require.NoError(t, err, "failed to send VerifyMFA\n%s", zet.Logs())
	require.True(t, verifyResp.Success, "VerifyMFA failed: error=%q code=%d\n%s", verifyResp.Error, verifyResp.Code, zet.Logs())

	verifyEvt := events.WaitFor(t, ctx, "mfa", "enrollment_verification", name)
	require.True(t, verifyEvt.Successful, "mfa:enrollment_verification Successful=%t after VerifyMFA, want true", verifyEvt.Successful)
	t.Logf("mfa:enrollment_verification reports Successful=%t after VerifyMFA", verifyEvt.Successful)
}

func testVerifyMFARejectsInvalidTotp(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	name := testutil.IdentityName(t)
	enrolled, _ := newEnrolledMFA(t, ctx, name)

	t.Logf("sending VerifyMFA with invalid TOTP for %q", name)
	verifyResp, err := enrolled.Client.VerifyMFA(ctx, enrolled.Identifier, "000000")
	require.NoError(t, err, "failed to send VerifyMFA\n%s", zet.Logs())
	require.False(t, verifyResp.Success, "VerifyMFA with invalid TOTP should fail but Success=true")
	require.Equal(t, 500, verifyResp.Code, "expected Code=500, got %d", verifyResp.Code)
	require.Contains(t, verifyResp.Error, "the token provided was invalid", "expected invalid-token error, got %q", verifyResp.Error)
	t.Logf("VerifyMFA correctly rejected invalid TOTP: code=%d error=%q", verifyResp.Code, verifyResp.Error)
}

func testMFAReauthenticationAcceptsValidTotp(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	name := testutil.IdentityName(t)
	enrolled, events := newEnrolledMFA(t, ctx, name)

	code, err := generateTotpCode(enrolled.Secret, time.Now())
	require.NoError(t, err, "failed to compute TOTP")

	t.Logf("sending VerifyMFA with valid TOTP for %q", name)
	verifyResp, err := enrolled.Client.VerifyMFA(ctx, enrolled.Identifier, code)
	require.NoError(t, err, "failed to send VerifyMFA\n%s", zet.Logs())
	require.True(t, verifyResp.Success, "VerifyMFA failed: error=%q code=%d\n%s", verifyResp.Error, verifyResp.Code, zet.Logs())
	verifyEvt := events.WaitFor(t, ctx, "mfa", "enrollment_verification", name)
	require.True(t, verifyEvt.Successful, "mfa:enrollment_verification Successful=%t after VerifyMFA, want true", verifyEvt.Successful)

	t.Logf("sending IdentityOnOff(false) for %q to drop the session", name)
	offResp, err := enrolled.Client.IdentityOnOff(ctx, enrolled.Identifier, false)
	require.NoError(t, err, "failed to send IdentityOnOff(false)\n%s", zet.Logs())
	require.True(t, offResp.Success, "IdentityOnOff(false) failed: error=%q code=%d", offResp.Error, offResp.Code)

	t.Logf("sending IdentityOnOff(true) for %q to force re-auth", name)
	onResp, err := enrolled.Client.IdentityOnOff(ctx, enrolled.Identifier, true)
	require.NoError(t, err, "failed to send IdentityOnOff(true)\n%s", zet.Logs())
	require.True(t, onResp.Success, "IdentityOnOff(true) failed: error=%q code=%d", onResp.Error, onResp.Code)

	events.WaitFor(t, ctx, "mfa", "auth_challenge", name)

	code, err = generateTotpCode(enrolled.Secret, time.Now())
	require.NoError(t, err, "failed to compute TOTP")

	t.Logf("sending SubmitMFA with valid TOTP for %q", name)
	submitResp, err := enrolled.Client.SubmitMFA(ctx, enrolled.Identifier, code)
	require.NoError(t, err, "failed to send SubmitMFA\n%s", zet.Logs())
	require.True(t, submitResp.Success, "SubmitMFA failed: error=%q code=%d\n%s", submitResp.Error, submitResp.Code, zet.Logs())

	submitEvt := events.WaitFor(t, ctx, "mfa", "mfa_auth_status", name)
	require.True(t, submitEvt.Successful, "mfa:mfa_auth_status Successful=%t after SubmitMFA, want true", submitEvt.Successful)
	t.Logf("mfa:mfa_auth_status reports Successful=%t after SubmitMFA", submitEvt.Successful)
}

func testMFAReauthenticationAcceptsRecoveryCode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	name := testutil.IdentityName(t)
	enrolled, events := newEnrolledMFA(t, ctx, name)

	code, err := generateTotpCode(enrolled.Secret, time.Now())
	require.NoError(t, err, "failed to compute TOTP")

	t.Logf("sending VerifyMFA with valid TOTP for %q", name)
	verifyResp, err := enrolled.Client.VerifyMFA(ctx, enrolled.Identifier, code)
	require.NoError(t, err, "failed to send VerifyMFA\n%s", zet.Logs())
	require.True(t, verifyResp.Success, "VerifyMFA failed: error=%q code=%d\n%s", verifyResp.Error, verifyResp.Code, zet.Logs())
	verifyEvt := events.WaitFor(t, ctx, "mfa", "enrollment_verification", name)
	require.True(t, verifyEvt.Successful, "mfa:enrollment_verification Successful=%t after VerifyMFA, want true", verifyEvt.Successful)

	t.Logf("sending IdentityOnOff(false) for %q to drop the session", name)
	offResp, err := enrolled.Client.IdentityOnOff(ctx, enrolled.Identifier, false)
	require.NoError(t, err, "failed to send IdentityOnOff(false)\n%s", zet.Logs())
	require.True(t, offResp.Success, "IdentityOnOff(false) failed: error=%q code=%d", offResp.Error, offResp.Code)

	t.Logf("sending IdentityOnOff(true) for %q to force re-auth", name)
	onResp, err := enrolled.Client.IdentityOnOff(ctx, enrolled.Identifier, true)
	require.NoError(t, err, "failed to send IdentityOnOff(true)\n%s", zet.Logs())
	require.True(t, onResp.Success, "IdentityOnOff(true) failed: error=%q code=%d", onResp.Error, onResp.Code)

	events.WaitFor(t, ctx, "mfa", "auth_challenge", name)

	t.Logf("sending SubmitMFA with recovery code for %q", name)
	submitResp, err := enrolled.Client.SubmitMFA(ctx, enrolled.Identifier, enrolled.RecoveryCodes[0])
	require.NoError(t, err, "failed to send SubmitMFA\n%s", zet.Logs())
	require.True(t, submitResp.Success, "SubmitMFA failed: error=%q code=%d\n%s", submitResp.Error, submitResp.Code, zet.Logs())

	submitEvt := events.WaitFor(t, ctx, "mfa", "mfa_auth_status", name)
	require.True(t, submitEvt.Successful, "mfa:mfa_auth_status Successful=%t after SubmitMFA, want true", submitEvt.Successful)
	t.Logf("mfa:mfa_auth_status reports Successful=%t after SubmitMFA with recovery code", submitEvt.Successful)
}

func testMFAReauthenticationRejectsInvalidTotp(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	name := testutil.IdentityName(t)
	enrolled, events := newEnrolledMFA(t, ctx, name)

	code, err := generateTotpCode(enrolled.Secret, time.Now())
	require.NoError(t, err, "failed to compute TOTP")

	t.Logf("sending VerifyMFA with valid TOTP for %q", name)
	verifyResp, err := enrolled.Client.VerifyMFA(ctx, enrolled.Identifier, code)
	require.NoError(t, err, "failed to send VerifyMFA\n%s", zet.Logs())
	require.True(t, verifyResp.Success, "VerifyMFA failed: error=%q code=%d\n%s", verifyResp.Error, verifyResp.Code, zet.Logs())
	verifyEvt := events.WaitFor(t, ctx, "mfa", "enrollment_verification", name)
	require.True(t, verifyEvt.Successful, "mfa:enrollment_verification Successful=%t after VerifyMFA, want true", verifyEvt.Successful)

	t.Logf("sending IdentityOnOff(false) for %q to drop the session", name)
	offResp, err := enrolled.Client.IdentityOnOff(ctx, enrolled.Identifier, false)
	require.NoError(t, err, "failed to send IdentityOnOff(false)\n%s", zet.Logs())
	require.True(t, offResp.Success, "IdentityOnOff(false) failed: error=%q code=%d", offResp.Error, offResp.Code)

	t.Logf("sending IdentityOnOff(true) for %q to force re-auth", name)
	onResp, err := enrolled.Client.IdentityOnOff(ctx, enrolled.Identifier, true)
	require.NoError(t, err, "failed to send IdentityOnOff(true)\n%s", zet.Logs())
	require.True(t, onResp.Success, "IdentityOnOff(true) failed: error=%q code=%d", onResp.Error, onResp.Code)

	events.WaitFor(t, ctx, "mfa", "auth_challenge", name)

	t.Logf("sending SubmitMFA with invalid TOTP for %q", name)
	submitResp, err := enrolled.Client.SubmitMFA(ctx, enrolled.Identifier, "000000")
	require.NoError(t, err, "failed to send SubmitMFA\n%s", zet.Logs())
	require.False(t, submitResp.Success, "SubmitMFA with invalid TOTP should fail but Success=true")
	require.Equal(t, 500, submitResp.Code, "expected Code=500, got %d", submitResp.Code)
	require.Contains(t, submitResp.Error, "the token provided was invalid", "expected invalid-token error, got %q", submitResp.Error)
	t.Logf("SubmitMFA correctly rejected invalid TOTP: code=%d error=%q", submitResp.Code, submitResp.Error)
}

func testRemoveMFAAcceptsValidTotp(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	name := testutil.IdentityName(t)
	enrolled, events := newEnrolledMFA(t, ctx, name)

	code, err := generateTotpCode(enrolled.Secret, time.Now())
	require.NoError(t, err, "failed to compute TOTP")

	t.Logf("sending VerifyMFA with valid TOTP for %q", name)
	verifyResp, err := enrolled.Client.VerifyMFA(ctx, enrolled.Identifier, code)
	require.NoError(t, err, "failed to send VerifyMFA\n%s", zet.Logs())
	require.True(t, verifyResp.Success, "VerifyMFA failed: error=%q code=%d\n%s", verifyResp.Error, verifyResp.Code, zet.Logs())
	verifyEvt := events.WaitFor(t, ctx, "mfa", "enrollment_verification", name)
	require.True(t, verifyEvt.Successful, "mfa:enrollment_verification Successful=%t after VerifyMFA, want true", verifyEvt.Successful)

	code, err = generateTotpCode(enrolled.Secret, time.Now())
	require.NoError(t, err, "failed to compute TOTP")

	t.Logf("sending RemoveMFA with valid TOTP for %q", name)
	removeResp, err := enrolled.Client.RemoveMFA(ctx, enrolled.Identifier, code)
	require.NoError(t, err, "failed to send RemoveMFA\n%s", zet.Logs())
	require.True(t, removeResp.Success, "RemoveMFA failed: error=%q code=%d\n%s", removeResp.Error, removeResp.Code, zet.Logs())

	removeEvt := events.WaitFor(t, ctx, "mfa", "enrollment_remove", name)
	require.True(t, removeEvt.Successful, "mfa:enrollment_remove Successful=%t after RemoveMFA, want true", removeEvt.Successful)
	t.Logf("mfa:enrollment_remove reports Successful=%t after RemoveMFA with TOTP", removeEvt.Successful)
}

func testRemoveMFAAcceptsRecoveryCode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	name := testutil.IdentityName(t)
	enrolled, events := newEnrolledMFA(t, ctx, name)

	code, err := generateTotpCode(enrolled.Secret, time.Now())
	require.NoError(t, err, "failed to compute TOTP")

	t.Logf("sending VerifyMFA with valid TOTP for %q", name)
	verifyResp, err := enrolled.Client.VerifyMFA(ctx, enrolled.Identifier, code)
	require.NoError(t, err, "failed to send VerifyMFA\n%s", zet.Logs())
	require.True(t, verifyResp.Success, "VerifyMFA failed: error=%q code=%d\n%s", verifyResp.Error, verifyResp.Code, zet.Logs())
	verifyEvt := events.WaitFor(t, ctx, "mfa", "enrollment_verification", name)
	require.True(t, verifyEvt.Successful, "mfa:enrollment_verification Successful=%t after VerifyMFA, want true", verifyEvt.Successful)

	t.Logf("sending RemoveMFA with recovery code for %q", name)
	removeResp, err := enrolled.Client.RemoveMFA(ctx, enrolled.Identifier, enrolled.RecoveryCodes[0])
	require.NoError(t, err, "failed to send RemoveMFA\n%s", zet.Logs())
	require.True(t, removeResp.Success, "RemoveMFA failed: error=%q code=%d\n%s", removeResp.Error, removeResp.Code, zet.Logs())

	removeEvt := events.WaitFor(t, ctx, "mfa", "enrollment_remove", name)
	require.True(t, removeEvt.Successful, "mfa:enrollment_remove Successful=%t after RemoveMFA, want true", removeEvt.Successful)
	t.Logf("mfa:enrollment_remove reports Successful=%t after RemoveMFA with recovery code", removeEvt.Successful)
}

func testRemoveMFARejectsInvalidTotp(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	name := testutil.IdentityName(t)
	enrolled, events := newEnrolledMFA(t, ctx, name)

	code, err := generateTotpCode(enrolled.Secret, time.Now())
	require.NoError(t, err, "failed to compute TOTP")

	t.Logf("sending VerifyMFA with valid TOTP for %q", name)
	verifyResp, err := enrolled.Client.VerifyMFA(ctx, enrolled.Identifier, code)
	require.NoError(t, err, "failed to send VerifyMFA\n%s", zet.Logs())
	require.True(t, verifyResp.Success, "VerifyMFA failed: error=%q code=%d\n%s", verifyResp.Error, verifyResp.Code, zet.Logs())
	events.WaitFor(t, ctx, "mfa", "enrollment_verification", name)

	t.Logf("sending RemoveMFA with invalid TOTP for %q", name)
	removeResp, err := enrolled.Client.RemoveMFA(ctx, enrolled.Identifier, "000000")
	require.NoError(t, err, "failed to send RemoveMFA\n%s", zet.Logs())
	require.False(t, removeResp.Success, "RemoveMFA with invalid TOTP should fail but Success=true")
	require.Equal(t, 500, removeResp.Code, "expected Code=500, got %d", removeResp.Code)
	require.Contains(t, removeResp.Error, "the token provided was invalid", "expected invalid-token error, got %q", removeResp.Error)
	t.Logf("RemoveMFA correctly rejected invalid TOTP: code=%d error=%q", removeResp.Code, removeResp.Error)
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

	t.Logf("creating JWT for %q", name)
	jwt, err := overlay.CreateIdentityJWT(ctx, name)
	require.NoError(t, err, "failed to create JWT")
	require.NotEmpty(t, jwt)

	events := testutil.SubscribeEvents(t, ctx, zet)
	client := testutil.OpenCommandPipe(t, ctx, zet)

	identityData := testutil.AddIdentityData{
		IdentityFilename: name,
		JwtContent:       &jwt,
	}
	addResp := testutil.Enroll(t, ctx, client, identityData)
	require.True(t, addResp.Success, "AddIdentity failed: error=%q code=%d", addResp.Error, addResp.Code)

	added := events.WaitFor(t, ctx, "identity", "added", name)
	require.NotEmpty(t, added.Id.Identifier, "identity:added Identifier empty")
	events.WaitFor(t, ctx, "controller", "connected", name)

	t.Logf("sending EnableMFA for %q", name)
	enrollment, err := client.GetMFAEnrollment(ctx, added.Id.Identifier)
	require.NoError(t, err, "failed to send EnableMFA\n%s", zet.Logs())
	require.NotEmpty(t, enrollment.ProvisioningUrl, "EnableMFA Data.ProvisioningUrl should be non-empty")
	require.NotEmpty(t, enrollment.RecoveryCodes, "EnableMFA Data.RecoveryCodes should be non-empty")
	t.Logf("EnableMFA returned ProvisioningUrl and %d recovery codes", len(enrollment.RecoveryCodes))

	parsed, err := url.Parse(enrollment.ProvisioningUrl)
	require.NoError(t, err, "failed to parse provisioning URL %q", enrollment.ProvisioningUrl)
	secret := parsed.Query().Get("secret")
	require.NotEmpty(t, secret, "provisioning url missing secret param: %q", enrollment.ProvisioningUrl)

	return &enrolledMFA{
		Client:        client,
		Identifier:    added.Id.Identifier,
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
