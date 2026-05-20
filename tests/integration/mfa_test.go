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
	testutil.RunTestWithTimeout(t, "acceptsJwtEnrolledIdentity", testEnableMFAAcceptsJwtEnrolledIdentity)
	testutil.RunTestWithTimeout(t, "acceptsTotpRequiredAuthPolicy", testEnableMFAAcceptsTotpRequiredAuthPolicy)
}

func TestVerifyMFA(t *testing.T) {
	testutil.RunTestWithTimeout(t, "acceptsValidTotp", testVerifyMFAAcceptsValidTotp)
	testutil.RunTestWithTimeout(t, "rejectsInvalidTotp", testVerifyMFARejectsInvalidTotp)
}

func TestMFAReauthentication(t *testing.T) {
	testutil.RunTestWithTimeout(t, "acceptsValidTotp", testMFAReauthenticationAcceptsValidTotp)
	testutil.RunTestWithTimeout(t, "acceptsRecoveryCode", testMFAReauthenticationAcceptsRecoveryCode)
	testutil.RunTestWithTimeout(t, "rejectsInvalidTotp", testMFAReauthenticationRejectsInvalidTotp)
}

func TestRemoveMFA(t *testing.T) {
	testutil.RunTestWithTimeout(t, "acceptsValidTotp", testRemoveMFAAcceptsValidTotp)
	testutil.RunTestWithTimeout(t, "acceptsRecoveryCode", testRemoveMFAAcceptsRecoveryCode)
	testutil.RunTestWithTimeout(t, "rejectsInvalidTotp", testRemoveMFARejectsInvalidTotp)
}

func testEnableMFAAcceptsJwtEnrolledIdentity(t *testing.T) {
	enrolled, _ := newEnrolledMFA(t, testutil.IdentityName(t))

	require.False(t, enrolled.IsVerified, "EnableMFA Data.IsVerified should be false before verify_mfa")
	t.Logf("EnableMFA returned IsVerified=%t", enrolled.IsVerified)
}

func testEnableMFAAcceptsTotpRequiredAuthPolicy(t *testing.T) {
	t.Skip("Tracking https://github.com/openziti/desktop-edge-win/issues/947 and https://openziti.discourse.group/t/enrolling-mfa-totp-from-zdew-fails/5482 - EnableMFA fails with 'failed to authenticate' for identities bound to TOTP-required auth policies")

	name := testutil.IdentityName(t)
	policy := name + "-policy"
	t.Logf("creating TOTP-required auth policy %q", policy)
	require.NoError(t, state.overlay.CreateAuthPolicyRequiringTOTP(policy), "create auth policy")

	t.Logf("creating JWT for %q bound to auth policy %q", name, policy)
	jwt, err := state.overlay.CreateIdentityJWTWithAuthPolicy(name, policy)
	require.NoError(t, err, "failed to create JWT for identity bound to %q", policy)
	require.NotEmpty(t, jwt)

	client := state.zetClient.Commands
	events := state.zetClient.Events

	identityData := testutil.AddIdentityData{
		IdentityFilename: name,
		JwtContent:       &jwt,
	}
	addResp := testutil.AddIdentity(t, client, identityData)
	require.True(t, addResp.Success, "AddIdentity failed: error=%q code=%d", addResp.Error, addResp.Code)

	added := events.WaitFor(t, "identity", "added", name)
	require.NotEmpty(t, added.Id.Identifier, "identity:added Identifier empty")
	testutil.AssertValidJwtEnrolledIdentityFile(t, added.Id.Identifier)

	t.Logf("sending EnableMFA for %q", name)
	enrollment, err := client.GetMFAEnrollment(added.Id.Identifier)
	require.NoError(t, err, "failed to send EnableMFA\n%s", state.zetClient.LogPath())
	require.NotEmpty(t, enrollment.ProvisioningUrl, "EnableMFA Data.ProvisioningUrl should be non-empty")
	require.NotEmpty(t, enrollment.RecoveryCodes, "EnableMFA Data.RecoveryCodes should be non-empty")
	t.Logf("EnableMFA returned ProvisioningUrl and %d recovery codes", len(enrollment.RecoveryCodes))
}

func testVerifyMFAAcceptsValidTotp(t *testing.T) {
	name := testutil.IdentityName(t)
	enrolled, events := newEnrolledMFA(t, name)

	code, err := generateTotpCode(enrolled.Secret, time.Now())
	require.NoError(t, err, "failed to compute TOTP")

	t.Logf("sending VerifyMFA with valid TOTP for %q", name)
	verifyResp, err := enrolled.Client.VerifyMFA(enrolled.Identifier, code)
	require.NoError(t, err, "failed to send VerifyMFA\n%s", state.zetClient.LogPath())
	require.True(t, verifyResp.Success, "VerifyMFA failed: error=%q code=%d\n%s", verifyResp.Error, verifyResp.Code, state.zetClient.LogPath())

	verifyEvt := events.WaitFor(t, "mfa", "enrollment_verification", name)
	require.True(t, verifyEvt.Successful, "mfa:enrollment_verification Successful=%t after VerifyMFA, want true", verifyEvt.Successful)
	t.Logf("mfa:enrollment_verification reports Successful=%t after VerifyMFA", verifyEvt.Successful)
}

func testVerifyMFARejectsInvalidTotp(t *testing.T) {
	name := testutil.IdentityName(t)
	enrolled, _ := newEnrolledMFA(t, name)

	t.Logf("sending VerifyMFA with invalid TOTP for %q", name)
	verifyResp, err := enrolled.Client.VerifyMFA(enrolled.Identifier, "000000")
	require.NoError(t, err, "failed to send VerifyMFA\n%s", state.zetClient.LogPath())
	require.False(t, verifyResp.Success, "VerifyMFA with invalid TOTP should fail but Success=true")
	require.Equal(t, 500, verifyResp.Code, "expected Code=500, got %d", verifyResp.Code)
	require.Contains(t, verifyResp.Error, "the token provided was invalid", "expected invalid-token error, got %q", verifyResp.Error)
	t.Logf("VerifyMFA rejected invalid TOTP: code=%d error=%q", verifyResp.Code, verifyResp.Error)
}

func testMFAReauthenticationAcceptsValidTotp(t *testing.T) {
	name := testutil.IdentityName(t)
	enrolled, events := newEnrolledMFA(t, name)

	code, err := generateTotpCode(enrolled.Secret, time.Now())
	require.NoError(t, err, "failed to compute TOTP")

	t.Logf("sending VerifyMFA with valid TOTP for %q", name)
	verifyResp, err := enrolled.Client.VerifyMFA(enrolled.Identifier, code)
	require.NoError(t, err, "failed to send VerifyMFA\n%s", state.zetClient.LogPath())
	require.True(t, verifyResp.Success, "VerifyMFA failed: error=%q code=%d\n%s", verifyResp.Error, verifyResp.Code, state.zetClient.LogPath())
	verifyEvt := events.WaitFor(t, "mfa", "enrollment_verification", name)
	require.True(t, verifyEvt.Successful, "mfa:enrollment_verification Successful=%t after VerifyMFA, want true", verifyEvt.Successful)

	t.Logf("sending IdentityOnOff(false) for %q to drop the session", name)
	offResp, err := enrolled.Client.IdentityOnOff(enrolled.Identifier, false)
	require.NoError(t, err, "failed to send IdentityOnOff(false)\n%s", state.zetClient.LogPath())
	require.True(t, offResp.Success, "IdentityOnOff(false) failed: error=%q code=%d", offResp.Error, offResp.Code)

	t.Logf("sending IdentityOnOff(true) for %q to force re-auth", name)
	onResp, err := enrolled.Client.IdentityOnOff(enrolled.Identifier, true)
	require.NoError(t, err, "failed to send IdentityOnOff(true)\n%s", state.zetClient.LogPath())
	require.True(t, onResp.Success, "IdentityOnOff(true) failed: error=%q code=%d", onResp.Error, onResp.Code)

	events.WaitFor(t, "mfa", "auth_challenge", name)

	code, err = generateTotpCode(enrolled.Secret, time.Now())
	require.NoError(t, err, "failed to compute TOTP")

	t.Logf("sending SubmitMFA with valid TOTP for %q", name)
	submitResp, err := enrolled.Client.SubmitMFA(enrolled.Identifier, code)
	require.NoError(t, err, "failed to send SubmitMFA\n%s", state.zetClient.LogPath())
	require.True(t, submitResp.Success, "SubmitMFA failed: error=%q code=%d\n%s", submitResp.Error, submitResp.Code, state.zetClient.LogPath())

	submitEvt := events.WaitFor(t, "mfa", "mfa_auth_status", name)
	require.True(t, submitEvt.Successful, "mfa:mfa_auth_status Successful=%t after SubmitMFA, want true", submitEvt.Successful)
	t.Logf("mfa:mfa_auth_status reports Successful=%t after SubmitMFA", submitEvt.Successful)
}

func testMFAReauthenticationAcceptsRecoveryCode(t *testing.T) {
	name := testutil.IdentityName(t)
	enrolled, events := newEnrolledMFA(t, name)

	code, err := generateTotpCode(enrolled.Secret, time.Now())
	require.NoError(t, err, "failed to compute TOTP")

	t.Logf("sending VerifyMFA with valid TOTP for %q", name)
	verifyResp, err := enrolled.Client.VerifyMFA(enrolled.Identifier, code)
	require.NoError(t, err, "failed to send VerifyMFA\n%s", state.zetClient.LogPath())
	require.True(t, verifyResp.Success, "VerifyMFA failed: error=%q code=%d\n%s", verifyResp.Error, verifyResp.Code, state.zetClient.LogPath())
	verifyEvt := events.WaitFor(t, "mfa", "enrollment_verification", name)
	require.True(t, verifyEvt.Successful, "mfa:enrollment_verification Successful=%t after VerifyMFA, want true", verifyEvt.Successful)

	t.Logf("sending IdentityOnOff(false) for %q to drop the session", name)
	offResp, err := enrolled.Client.IdentityOnOff(enrolled.Identifier, false)
	require.NoError(t, err, "failed to send IdentityOnOff(false)\n%s", state.zetClient.LogPath())
	require.True(t, offResp.Success, "IdentityOnOff(false) failed: error=%q code=%d", offResp.Error, offResp.Code)

	t.Logf("sending IdentityOnOff(true) for %q to force re-auth", name)
	onResp, err := enrolled.Client.IdentityOnOff(enrolled.Identifier, true)
	require.NoError(t, err, "failed to send IdentityOnOff(true)\n%s", state.zetClient.LogPath())
	require.True(t, onResp.Success, "IdentityOnOff(true) failed: error=%q code=%d", onResp.Error, onResp.Code)

	events.WaitFor(t, "mfa", "auth_challenge", name)

	t.Logf("sending SubmitMFA with recovery code for %q", name)
	submitResp, err := enrolled.Client.SubmitMFA(enrolled.Identifier, enrolled.RecoveryCodes[0])
	require.NoError(t, err, "failed to send SubmitMFA\n%s", state.zetClient.LogPath())
	require.True(t, submitResp.Success, "SubmitMFA failed: error=%q code=%d\n%s", submitResp.Error, submitResp.Code, state.zetClient.LogPath())

	submitEvt := events.WaitFor(t, "mfa", "mfa_auth_status", name)
	require.True(t, submitEvt.Successful, "mfa:mfa_auth_status Successful=%t after SubmitMFA, want true", submitEvt.Successful)
	t.Logf("mfa:mfa_auth_status reports Successful=%t after SubmitMFA with recovery code", submitEvt.Successful)
}

func testMFAReauthenticationRejectsInvalidTotp(t *testing.T) {
	name := testutil.IdentityName(t)
	enrolled, events := newEnrolledMFA(t, name)

	code, err := generateTotpCode(enrolled.Secret, time.Now())
	require.NoError(t, err, "failed to compute TOTP")

	t.Logf("sending VerifyMFA with valid TOTP for %q", name)
	verifyResp, err := enrolled.Client.VerifyMFA(enrolled.Identifier, code)
	require.NoError(t, err, "failed to send VerifyMFA\n%s", state.zetClient.LogPath())
	require.True(t, verifyResp.Success, "VerifyMFA failed: error=%q code=%d\n%s", verifyResp.Error, verifyResp.Code, state.zetClient.LogPath())
	verifyEvt := events.WaitFor(t, "mfa", "enrollment_verification", name)
	require.True(t, verifyEvt.Successful, "mfa:enrollment_verification Successful=%t after VerifyMFA, want true", verifyEvt.Successful)

	t.Logf("sending IdentityOnOff(false) for %q to drop the session", name)
	offResp, err := enrolled.Client.IdentityOnOff(enrolled.Identifier, false)
	require.NoError(t, err, "failed to send IdentityOnOff(false)\n%s", state.zetClient.LogPath())
	require.True(t, offResp.Success, "IdentityOnOff(false) failed: error=%q code=%d", offResp.Error, offResp.Code)

	t.Logf("sending IdentityOnOff(true) for %q to force re-auth", name)
	onResp, err := enrolled.Client.IdentityOnOff(enrolled.Identifier, true)
	require.NoError(t, err, "failed to send IdentityOnOff(true)\n%s", state.zetClient.LogPath())
	require.True(t, onResp.Success, "IdentityOnOff(true) failed: error=%q code=%d", onResp.Error, onResp.Code)

	events.WaitFor(t, "mfa", "auth_challenge", name)

	t.Logf("sending SubmitMFA with invalid TOTP for %q", name)
	submitResp, err := enrolled.Client.SubmitMFA(enrolled.Identifier, "000000")
	require.NoError(t, err, "failed to send SubmitMFA\n%s", state.zetClient.LogPath())
	require.False(t, submitResp.Success, "SubmitMFA with invalid TOTP should fail but Success=true")
	require.Equal(t, 500, submitResp.Code, "expected Code=500, got %d", submitResp.Code)
	require.Contains(t, submitResp.Error, "the token provided was invalid", "expected invalid-token error, got %q", submitResp.Error)
	t.Logf("SubmitMFA rejected invalid TOTP: code=%d error=%q", submitResp.Code, submitResp.Error)
}

func testRemoveMFAAcceptsValidTotp(t *testing.T) {
	name := testutil.IdentityName(t)
	enrolled, events := newEnrolledMFA(t, name)

	code, err := generateTotpCode(enrolled.Secret, time.Now())
	require.NoError(t, err, "failed to compute TOTP")

	t.Logf("sending VerifyMFA with valid TOTP for %q", name)
	verifyResp, err := enrolled.Client.VerifyMFA(enrolled.Identifier, code)
	require.NoError(t, err, "failed to send VerifyMFA\n%s", state.zetClient.LogPath())
	require.True(t, verifyResp.Success, "VerifyMFA failed: error=%q code=%d\n%s", verifyResp.Error, verifyResp.Code, state.zetClient.LogPath())
	verifyEvt := events.WaitFor(t, "mfa", "enrollment_verification", name)
	require.True(t, verifyEvt.Successful, "mfa:enrollment_verification Successful=%t after VerifyMFA, want true", verifyEvt.Successful)

	code, err = generateTotpCode(enrolled.Secret, time.Now())
	require.NoError(t, err, "failed to compute TOTP")

	t.Logf("sending RemoveMFA with valid TOTP for %q", name)
	removeResp, err := enrolled.Client.RemoveMFA(enrolled.Identifier, code)
	require.NoError(t, err, "failed to send RemoveMFA\n%s", state.zetClient.LogPath())
	require.True(t, removeResp.Success, "RemoveMFA failed: error=%q code=%d\n%s", removeResp.Error, removeResp.Code, state.zetClient.LogPath())

	removeEvt := events.WaitFor(t, "mfa", "enrollment_remove", name)
	require.True(t, removeEvt.Successful, "mfa:enrollment_remove Successful=%t after RemoveMFA, want true", removeEvt.Successful)
	t.Logf("mfa:enrollment_remove reports Successful=%t after RemoveMFA with TOTP", removeEvt.Successful)
}

func testRemoveMFAAcceptsRecoveryCode(t *testing.T) {
	name := testutil.IdentityName(t)
	enrolled, events := newEnrolledMFA(t, name)

	code, err := generateTotpCode(enrolled.Secret, time.Now())
	require.NoError(t, err, "failed to compute TOTP")

	t.Logf("sending VerifyMFA with valid TOTP for %q", name)
	verifyResp, err := enrolled.Client.VerifyMFA(enrolled.Identifier, code)
	require.NoError(t, err, "failed to send VerifyMFA\n%s", state.zetClient.LogPath())
	require.True(t, verifyResp.Success, "VerifyMFA failed: error=%q code=%d\n%s", verifyResp.Error, verifyResp.Code, state.zetClient.LogPath())
	verifyEvt := events.WaitFor(t, "mfa", "enrollment_verification", name)
	require.True(t, verifyEvt.Successful, "mfa:enrollment_verification Successful=%t after VerifyMFA, want true", verifyEvt.Successful)

	t.Logf("sending RemoveMFA with recovery code for %q", name)
	removeResp, err := enrolled.Client.RemoveMFA(enrolled.Identifier, enrolled.RecoveryCodes[0])
	require.NoError(t, err, "failed to send RemoveMFA\n%s", state.zetClient.LogPath())
	require.True(t, removeResp.Success, "RemoveMFA failed: error=%q code=%d\n%s", removeResp.Error, removeResp.Code, state.zetClient.LogPath())

	removeEvt := events.WaitFor(t, "mfa", "enrollment_remove", name)
	require.True(t, removeEvt.Successful, "mfa:enrollment_remove Successful=%t after RemoveMFA, want true", removeEvt.Successful)
	t.Logf("mfa:enrollment_remove reports Successful=%t after RemoveMFA with recovery code", removeEvt.Successful)
}

func testRemoveMFARejectsInvalidTotp(t *testing.T) {
	name := testutil.IdentityName(t)
	enrolled, events := newEnrolledMFA(t, name)

	code, err := generateTotpCode(enrolled.Secret, time.Now())
	require.NoError(t, err, "failed to compute TOTP")

	t.Logf("sending VerifyMFA with valid TOTP for %q", name)
	verifyResp, err := enrolled.Client.VerifyMFA(enrolled.Identifier, code)
	require.NoError(t, err, "failed to send VerifyMFA\n%s", state.zetClient.LogPath())
	require.True(t, verifyResp.Success, "VerifyMFA failed: error=%q code=%d\n%s", verifyResp.Error, verifyResp.Code, state.zetClient.LogPath())
	events.WaitFor(t, "mfa", "enrollment_verification", name)

	t.Logf("sending RemoveMFA with invalid TOTP for %q", name)
	removeResp, err := enrolled.Client.RemoveMFA(enrolled.Identifier, "000000")
	require.NoError(t, err, "failed to send RemoveMFA\n%s", state.zetClient.LogPath())
	require.False(t, removeResp.Success, "RemoveMFA with invalid TOTP should fail but Success=true")
	require.Equal(t, 500, removeResp.Code, "expected Code=500, got %d", removeResp.Code)
	require.Contains(t, removeResp.Error, "the token provided was invalid", "expected invalid-token error, got %q", removeResp.Error)
	t.Logf("RemoveMFA rejected invalid TOTP: code=%d error=%q", removeResp.Code, removeResp.Error)
}

type enrolledMFA struct {
	Client        *testutil.CommandsClient
	Identifier    string
	IsVerified    bool
	RecoveryCodes []string
	Secret        string
}

func newEnrolledMFA(t *testing.T, name string) (*enrolledMFA, *testutil.EventClient) {
	t.Logf("creating JWT for %q", name)
	jwt, err := state.overlay.CreateIdentityJWT(name)
	require.NoError(t, err, "failed to create JWT")
	require.NotEmpty(t, jwt)

	client := state.zetClient.Commands
	events := state.zetClient.Events

	identityData := testutil.AddIdentityData{
		IdentityFilename: name,
		JwtContent:       &jwt,
	}
	addResp := testutil.AddIdentity(t, client, identityData)
	require.True(t, addResp.Success, "AddIdentity failed: error=%q code=%d", addResp.Error, addResp.Code)

	added := events.WaitFor(t, "identity", "added", name)
	require.NotEmpty(t, added.Id.Identifier, "identity:added Identifier empty")
	testutil.AssertValidJwtEnrolledIdentityFile(t, added.Id.Identifier)
	events.WaitFor(t, "controller", "connected", name)

	t.Logf("sending EnableMFA for %q", name)
	enrollment, err := client.GetMFAEnrollment(added.Id.Identifier)
	require.NoError(t, err, "failed to send EnableMFA\n%s", state.zetClient.LogPath())
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
