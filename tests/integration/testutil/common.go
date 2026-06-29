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

// Shared, cross-cutting test helpers that span more than one component (overlay,
// zet, ipc, identity file). Helpers specific to a single component live with it.

package testutil

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const workingExtJwtSignerName = "test_ext_auth_signer_working"

// EnrollJwt enrolls jwt on zet, waits for the identity:added event,
// asserts the on-disk identity file, and returns the added event. The JWT may
// come from a freshly created identity or a pre-imported one.
func EnrollJwt(t *testing.T, zet *ZET, name, jwt string) IdentityEvent {
	identityData := NewJwtIdentityData(name, jwt)
	addResp := zet.AddIdentity(t, identityData)
	addResp.AssertSuccess()

	added := zet.WaitForIdentityEvent(t, "added", name)
	require.NotEmpty(t, added.Id.Identifier, "identity:added Identifier empty")
	require.True(t, added.Id.Active, "identity:added Active=%t", added.Id.Active)
	AssertValidJwtEnrolledIdentityFile(t, added.Id.Identifier)
	return added
}

// FetchAndEnrollJwt fetches the pending OTT enrollment JWT for a pre-imported
// identity and enrolls it on zet, returning the added event.
func FetchAndEnrollJwt(t *testing.T, overlay *Overlay, zet *ZET, name string) IdentityEvent {
	jwt := overlay.GetJwtFromController(t, name)
	identityEvent := EnrollJwt(t, zet, name, jwt)
	return identityEvent
}

// ParseTOTPSecret extracts the base32 TOTP secret from an otpauth provisioning URL.
func ParseTOTPSecret(t *testing.T, provisioningURL string) string {
	parsed, err := url.Parse(provisioningURL)
	require.NoError(t, err, "parse provisioning URL")
	secret := parsed.Query().Get("secret")
	require.NotEmpty(t, secret, "provisioning url missing secret param")
	return secret
}

// EnrollAndVerifyMFA enrolls the pre-imported identity on zet, enables MFA, and
// completes enrollment with a valid TOTP, asserting the VerifyMFA response and
// the mfa:enrollment_verification event report success. Returns the enrollment
// and its TOTP secret.
func EnrollAndVerifyMFA(t *testing.T, overlay *Overlay, zet *ZET, name string) (MFAEnrollment, string) {
	added := FetchAndEnrollJwt(t, overlay, zet, name)
	require.False(t, added.Id.MfaEnabled, "identity:added MfaEnabled=%t before EnableMFA", added.Id.MfaEnabled)
	zet.WaitForControllerEvent(t, "connected", name)

	enableResp := zet.EnableMFA(t, added.Id.Identifier)
	enableResp.AssertSuccess()
	require.NotEmpty(t, enableResp.Data.ProvisioningUrl, "EnableMFA Data.ProvisioningUrl should be non-empty")
	require.NotEmpty(t, enableResp.Data.RecoveryCodes, "EnableMFA Data.RecoveryCodes should be non-empty")
	require.False(t, enableResp.Data.IsVerified, "EnableMFA Data.IsVerified should be false before verify_mfa")
	enrollment := enableResp.Data
	enrollment.Identifier = added.Id.Identifier

	challengeEvent := zet.WaitForMfaEvent(t, "enrollment_challenge", name)
	challengeEvent.AssertSuccess()

	secret := ParseTOTPSecret(t, enrollment.ProvisioningUrl)
	code := GenerateTOTP(t, secret, time.Now())

	verifyResp := zet.VerifyMFA(t, enrollment.Identifier, code)
	verifyResp.AssertSuccess()

	updatedEvent := zet.WaitForIdentityEvent(t, "updated", name)
	updatedEvent.AssertMfaAuthenticated()

	verificationEvent := zet.WaitForMfaEvent(t, "enrollment_verification", name)
	verificationEvent.AssertSuccess()

	return enrollment, secret
}

// GenerateTOTP derives the current TOTP for the base32-encoded secret.
func GenerateTOTP(t *testing.T, secret string, at time.Time) string {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimRight(secret, "=")))
	require.NoError(t, err, "base32 decode secret")
	counter := uint64(at.Unix() / 30)
	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", code%1_000_000)
}

// EnrollUrlIdentityToNone adds name to zet by controller URL (enroll-to-none),
// waits for the needs_ext_login event, asserts NeedsExtAuth and the on-disk
// file, and returns the event.
func EnrollUrlIdentityToNone(t *testing.T, overlay *Overlay, zet *ZET, name string) IdentityEvent {
	identityData := NewUrlIdentityData(name, overlay.ControllerHostPort(), EnrollModeNone)
	addResp := zet.AddIdentity(t, identityData)
	addResp.AssertSuccess()

	event := zet.WaitForIdentityEvent(t, "needs_ext_login", name)
	require.NotEmpty(t, event.Id.Identifier, "identity:needs_ext_login Identifier empty")
	require.True(t, event.Id.NeedsExtAuth, "identity:needs_ext_login NeedsExtAuth=%t", event.Id.NeedsExtAuth)
	AssertValidUrlEnrolledIdentityFile(t, event.Id.Identifier, EnrollModeNone)
	return event
}

// SetupWorkingExtJwtSigner adopts idp.SignerName when set (failing if it does
// not exist on the controller), otherwise creates or reuses a harness signer.
// Returns the signer name and id.
func SetupWorkingExtJwtSigner(t *testing.T, overlay *Overlay, idp *IdP) (string, string) {
	if idp.SignerName != "" {
		id, found := overlay.FindExtJwtSignerId(t, idp.SignerName)
		if !found {
			t.Fatalf("idp.signerName=%q is set but no ext-jwt-signer with that name exists on the controller; fix the name or create the signer", idp.SignerName)
		}
		return idp.SignerName, id
	}

	if !idp.UseTestHarnessIdP {
		t.Fatal("idp.signerName is empty: the working ext-jwt-signer is only auto-created when the harness runs its own IdP (useTestHarnessIdP=true); set idp.signerName to use your own")
	}

	if id, found := overlay.FindExtJwtSignerId(t, workingExtJwtSignerName); found {
		return workingExtJwtSignerName, id
	}
	id := overlay.CreateExtJwtSigner(t, ExtJwtSignerSpec{
		Name:     workingExtJwtSignerName,
		Issuer:   idp.IssuerURL,
		JWKS:     idp.JWKSURI(),
		ClientID: idp.ClientIDWorks,
		Audience: idp.Audience,
		Claim:    "email",
		Scopes:   strings.Fields(idp.Scopes),
	})
	return workingExtJwtSignerName, id
}

// parseVersion splits a "vX.XX.X" style version into its major and minor numbers.
func parseVersion(version string) (int, int, error) {
	parts := strings.Split(strings.TrimPrefix(version, "v"), ".")
	if len(parts) < 2 {
		return 0, 0, fmt.Errorf("unparsable version %q", version)
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("unparsable version %q: %w", version, err)
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("unparsable version %q: %w", version, err)
	}
	return major, minor, nil
}
