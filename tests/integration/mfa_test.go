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
	"encoding/json"
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
}

func TestVerifyMFA(t *testing.T) {
	t.Run("withValidTotp", testVerifyMFAWithValidTotp)
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

	for {
		raw, err := events.ReadEvent(ctx)
		require.NoError(t, err, "read event waiting for controller:connected\n%s", zet.Logs())

		var event struct {
			Op, Action, Fingerprint string
		}
		require.NoError(t, json.Unmarshal(raw, &event), "parse event: %s", raw)
		if event.Op != "controller" || event.Action != "connected" || event.Fingerprint != name {
			t.Logf("skipped event: Op=%s Action=%s Fingerprint=%s", event.Op, event.Action, event.Fingerprint)
			continue
		}
		t.Logf("controller:connected received for %q", name)
		break
	}

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

	for {
		raw, err := events.ReadEvent(ctx)
		require.NoError(t, err, "read event waiting for controller:connected\n%s", zet.Logs())

		var event struct {
			Op, Action, Fingerprint string
		}
		require.NoError(t, json.Unmarshal(raw, &event), "parse event: %s", raw)
		if event.Op != "controller" || event.Action != "connected" || event.Fingerprint != name {
			t.Logf("skipped event: Op=%s Action=%s Fingerprint=%s", event.Op, event.Action, event.Fingerprint)
			continue
		}
		t.Logf("controller:connected received for %q", name)
		break
	}

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

	code, err := totpCode(secret, time.Now())
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
}

func totpCode(secret string, at time.Time) (string, error) {
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
