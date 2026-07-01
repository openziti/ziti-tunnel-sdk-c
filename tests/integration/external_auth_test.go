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
	"testing"

	"github.com/openziti/ziti-tunnel-sdk-c/tests/integration/testutil"
	"github.com/stretchr/testify/require"
)

type extJwtSigner struct {
	name string
	id   string
}

type extAuthContext struct {
	overlay       *testutil.Overlay
	idp           *testutil.IdP
	zet           *testutil.ZET
	workingSigner extJwtSigner
	extraSignerA  extJwtSigner
	extraSignerB  extJwtSigner
}

func newExtAuthContext(t *testing.T) *extAuthContext {
	state.overlay.RequireCATrusted(t)
	state.idp.RequireConfigured(t)
	c := &extAuthContext{
		overlay: state.overlay,
		idp:     state.idp,
		zet:     state.zetClient,
	}
	c.workingSigner.name, c.workingSigner.id = testutil.SetupWorkingExtJwtSigner(t, c.overlay, c.idp)
	return c
}

func (c *extAuthContext) setupExtraExtJwtSigners(t *testing.T) {
	c.extraSignerA.name = "test_ext_auth_signer_extra_a"
	c.extraSignerA.id = c.overlay.CreateExtJwtSigner(t, testutil.ExtJwtSignerSpec{
		Name:     c.extraSignerA.name,
		Issuer:   c.idp.IssuerURL + "-" + c.extraSignerA.name,
		JWKS:     c.idp.JWKSURI() + "-" + c.extraSignerA.name,
		ClientID: c.idp.ClientIDExtraA,
		Audience: c.idp.Audience,
		Claim:    "email",
		Scopes:   c.idp.ScopeList(),
	})

	c.extraSignerB.name = "test_ext_auth_signer_extra_b"
	c.extraSignerB.id = c.overlay.CreateExtJwtSigner(t, testutil.ExtJwtSignerSpec{
		Name:     c.extraSignerB.name,
		Issuer:   c.idp.IssuerURL + "-" + c.extraSignerB.name,
		JWKS:     c.idp.JWKSURI() + "-" + c.extraSignerB.name,
		ClientID: c.idp.ClientIDExtraB,
		Audience: c.idp.Audience,
		Claim:    "email",
		Scopes:   c.idp.ScopeList(),
	})
}

func TestExternalAuthMultipleSigners(t *testing.T) {
	c := newExtAuthContext(t)
	c.setupExtraExtJwtSigners(t)

	t.Run("enrollToNoneMultipleSignersDefaultPolicyCompletes", c.enrollToNoneMultipleSignersDefaultPolicyCompletes)
	t.Run("enrollToNoneMultipleSignersNamedPolicyCompletes", c.enrollToNoneMultipleSignersNamedPolicyCompletes)

	_ = c.overlay.DeleteExtJwtSigner(c.extraSignerA.name)
	_ = c.overlay.DeleteExtJwtSigner(c.extraSignerB.name)
}

func TestExternalAuthSingleSigner(t *testing.T) {
	c := newExtAuthContext(t)

	t.Run("enrollToNoneCompletes", c.enrollToNoneCompletes)
	t.Run("enrollToNoneRejectsInvalidProvider", c.enrollToNoneRejectsInvalidProvider)
	t.Run("enrollToNoneRejectsUnknownControllerIdentity", c.enrollToNoneRejectsUnknownControllerIdentity)

	if c.overlay.ZitiMajor < 2 {
		t.Logf("skipping enroll-to-cert/token/both phases: controller is v%d.%d (requires ziti 2.0+)", c.overlay.ZitiMajor, c.overlay.ZitiMinor)
		return
	}

	t.Run("enrollToCertCompletes", c.enrollToCertCompletes)
	t.Run("enrollToCertUsesNameClaimSelector", c.enrollToCertUsesNameClaimSelector)
	t.Run("enrollToTokenCompletes", c.enrollToTokenCompletes)
	t.Run("enrollToTokenUsesNameClaimSelector", c.enrollToTokenUsesNameClaimSelector)
	t.Run("enrollToCertUsesAttrClaimSelector", c.enrollToCertUsesAttrClaimSelector)
	t.Run("enrollToTokenUsesAttrClaimSelector", c.enrollToTokenUsesAttrClaimSelector)
	t.Run("enrollToCertUsesMultipleAttrClaims", c.enrollToCertUsesMultipleAttrClaims)
	t.Run("enrollToTokenUsesMultipleAttrClaims", c.enrollToTokenUsesMultipleAttrClaims)
	t.Run("enrollToCertUsesEnrollAuthPolicy", c.enrollToCertUsesEnrollAuthPolicy)
	t.Run("enrollToTokenUsesEnrollAuthPolicy", c.enrollToTokenUsesEnrollAuthPolicy)
	t.Run("bothEnrollFlowsCompleteWhenBothEnabled", c.bothEnrollFlowsCompleteWhenBothEnabled)
	t.Run("enrollToNoneThenCertRejected", c.enrollToNoneThenCertRejected)
	t.Run("enrollToCertThenNoneRejected", c.enrollToCertThenNoneRejected)
	t.Run("enrollToCertThenTokenRejected", c.enrollToCertThenTokenRejected)
	t.Run("enrollToTokenThenCertRejected", c.enrollToTokenThenCertRejected)
}

func (c *extAuthContext) enrollToNoneCompletes(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		idName := "test_ext_auth_none_happy"
		idEvent := testutil.EnrollUrlIdentityToNone(t, c.overlay, c.zet, idName)
		authURL := c.zet.GetExternalAuthURL(t, idEvent.Id.Identifier, c.workingSigner.name)

		c.idp.DriveIdPFlow(t, authURL, idName+"@test.com")

		c.assertEnrollmentSucceeded(t, idName, testutil.EnrollModeNone)
	})
}

func (c *extAuthContext) enrollToNoneRejectsInvalidProvider(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		idName := "test_ext_auth_invalid_provider"
		idEvent := testutil.EnrollUrlIdentityToNone(t, c.overlay, c.zet, idName)

		bogusProvider := c.workingSigner.name + "-bogus"
		extAuthResp := c.zet.ExternalAuth(t, idEvent.Id.Identifier, bogusProvider)
		extAuthResp.AssertFail(500, "invalid provider")
	})
}

func (c *extAuthContext) enrollToNoneRejectsUnknownControllerIdentity(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		idName := "test_ext_auth_unknown_identity"
		// Deliberately DO NOT create a controller identity with externalId. The
		// OIDC flow at the IdP still succeeds, but the controller rejects login
		// since nothing maps this test's user to a known identity.

		idEvent := testutil.EnrollUrlIdentityToNone(t, c.overlay, c.zet, idName)

		authURL := c.zet.GetExternalAuthURL(t, idEvent.Id.Identifier, c.workingSigner.name)

		c.idp.DriveIdPFlow(t, authURL, idName+"@test.com")

		c.zet.WaitForControllerEvent(t, "disconnected", idName)
	})
}

func (c *extAuthContext) enrollToNoneMultipleSignersDefaultPolicyCompletes(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		idName := "test_ext_auth_multi_default"
		idEvent := testutil.EnrollUrlIdentityToNone(t, c.overlay, c.zet, idName)
		require.Subset(t, idEvent.Id.ExtAuthProviders, []string{c.workingSigner.name, c.extraSignerA.name, c.extraSignerB.name}, "identity:needs_ext_login ExtAuthProviders should contain all three signers, got %v", idEvent.Id.ExtAuthProviders)

		authURL := c.zet.GetExternalAuthURL(t, idEvent.Id.Identifier, c.workingSigner.name)

		c.idp.DriveIdPFlow(t, authURL, idName+"@test.com")

		c.assertEnrollmentSucceeded(t, idName, testutil.EnrollModeNone)
	})
}

func (c *extAuthContext) enrollToNoneMultipleSignersNamedPolicyCompletes(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		idName := "test_ext_auth_multi_named"

		policyName := "test_ext_auth_multi_named_policy"
		c.overlay.CreateAuthPolicyForExtJwt(t, policyName, c.workingSigner.id, c.extraSignerA.id, c.extraSignerB.id)

		c.overlay.CreateIdentityWithExternalId(t, idName, idName+"@test.com", policyName)

		idEvent := testutil.EnrollUrlIdentityToNone(t, c.overlay, c.zet, idName)
		require.Subset(t, idEvent.Id.ExtAuthProviders, []string{c.workingSigner.name, c.extraSignerA.name, c.extraSignerB.name}, "identity:needs_ext_login ExtAuthProviders should contain all three signers, got %v", idEvent.Id.ExtAuthProviders)

		authURL := c.zet.GetExternalAuthURL(t, idEvent.Id.Identifier, c.workingSigner.name)

		c.idp.DriveIdPFlow(t, authURL, idName+"@test.com")

		c.assertEnrollmentSucceeded(t, idName, testutil.EnrollModeNone)
	})
}

func (c *extAuthContext) enrollToCertCompletes(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		c.overlay.UpdateExtJwtSigner(t, c.workingSigner.name, testutil.ExtJwtSignerSpec{EnrollToCert: true})
		c.completeEnrollToCert(t, "test_ext_auth_cert_happy")
	})
}

// beginEnrollment sends AddIdentity and returns the enrollment URL the IdP flow
// continues at, asserting the response succeeded and carried a URL.
func (c *extAuthContext) beginEnrollment(t *testing.T, identityData testutil.AddIdentityData) string {
	addResp := c.zet.AddIdentity(t, identityData)
	addResp.AssertSuccess()
	require.NotEmpty(t, addResp.Data.URL, "AddIdentity response has empty URL")
	return addResp.Data.URL
}

// assertEnrollmentSucceeded waits for the identity:added event, asserts the identity is
// active with no pending ext-auth, validates its on-disk file for mode, and returns it.
func (c *extAuthContext) assertEnrollmentSucceeded(t *testing.T, idName string, mode testutil.EnrollMode) testutil.IdentityEvent {
	idAddedEvent := c.zet.WaitForIdentityEvent(t, "added", idName)
	require.True(t, idAddedEvent.Id.Active)
	require.False(t, idAddedEvent.Id.NeedsExtAuth)
	testutil.AssertValidUrlEnrolledIdentityFile(t, idAddedEvent.Id.Identifier, mode)
	return idAddedEvent
}

// completeEnrollToCert drives a full enroll-to-cert flow for name and returns the
// identity:added event. The working signer must already have EnrollToCert enabled.
func (c *extAuthContext) completeEnrollToCert(t *testing.T, name string) testutil.IdentityEvent {
	identityData := testutil.NewUrlIdentityData(name, c.overlay.ControllerHostPort(), testutil.EnrollModeCert, c.workingSigner.name)
	authURL := c.beginEnrollment(t, identityData)

	c.idp.DriveIdPFlow(t, authURL, name+"@test.com")

	return c.assertEnrollmentSucceeded(t, name, testutil.EnrollModeCert)
}

// Asserts a URL-enrolled identity is provisioned with the name the ext-jwt-signer's
// --enroll-name-claims-selector flag resolves to.
func (c *extAuthContext) assertExpectedIdentityName(t *testing.T, idEvent testutil.IdentityEvent, idName string) {
	require.Contains(t, idEvent.Id.Name, idName)
	idAddedEvent := c.zet.WaitForIdentityEvent(t, "added", idName)
	require.Equal(t, idName+"@test.com", idAddedEvent.Id.Name)
}

func (c *extAuthContext) enrollToCertUsesNameClaimSelector(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		c.overlay.UpdateExtJwtSigner(t, c.workingSigner.name, testutil.ExtJwtSignerSpec{EnrollToCert: true, EnrollNameSelector: "/email"})
		idName := "test_ext_auth_name_selector"
		idEvent := c.completeEnrollToCert(t, idName)
		c.assertExpectedIdentityName(t, idEvent, idName)
	})
}

func (c *extAuthContext) enrollToTokenCompletes(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		c.overlay.UpdateExtJwtSigner(t, c.workingSigner.name, testutil.ExtJwtSignerSpec{EnrollToToken: true})
		c.completeEnrollToToken(t, "test_ext_auth_token_happy")
	})
}

// completeEnrollToToken drives a full enroll-to-token flow for name and returns the
// identity:added event. The working signer must already have EnrollToToken enabled.
func (c *extAuthContext) completeEnrollToToken(t *testing.T, name string) testutil.IdentityEvent {
	identityData := testutil.NewUrlIdentityData(name, c.overlay.ControllerHostPort(), testutil.EnrollModeToken, c.workingSigner.name)
	authURL := c.beginEnrollment(t, identityData)

	c.idp.DriveIdPFlow(t, authURL, name+"@test.com")

	idEvent := c.zet.WaitForIdentityEvent(t, "needs_ext_login", name)
	require.True(t, idEvent.Id.NeedsExtAuth)
	authURL = c.zet.GetExternalAuthURL(t, idEvent.Id.Identifier, c.workingSigner.name)

	c.idp.DriveIdPFlow(t, authURL, name+"@test.com")

	return c.assertEnrollmentSucceeded(t, name, testutil.EnrollModeToken)
}

// assertGrantedServices waits for a bulk service event and asserts the identity was
// granted the expected services. The fixture gates services on #ziti-user and
// #ziti-admin, so the granted set reflects the attributes the selector applied.
func (c *extAuthContext) assertGrantedServices(t *testing.T, idName string, expected ...string) {
	bulkServiceEvent := c.zet.WaitForBulkServiceEvent(t, "updated", idName)
	grantedServices := []string{}
	for _, s := range bulkServiceEvent.AddedServices {
		grantedServices = append(grantedServices, s.Name)
	}
	require.ElementsMatch(t, expected, grantedServices)
}

func (c *extAuthContext) enrollToCertUsesAttrClaimSelector(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		c.overlay.UpdateExtJwtSigner(t, c.workingSigner.name, testutil.ExtJwtSignerSpec{EnrollToCert: true, EnrollAttrSelector: "/groups"})
		idName := "test_ext_auth_attr_selector"
		c.completeEnrollToCert(t, idName)
		c.assertGrantedServices(t, idName, "test_ext_auth_attr_user_svc")
	})
}

func (c *extAuthContext) enrollToTokenUsesAttrClaimSelector(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		c.overlay.UpdateExtJwtSigner(t, c.workingSigner.name, testutil.ExtJwtSignerSpec{EnrollToToken: true, EnrollAttrSelector: "/groups"})
		idName := "test_ext_auth_token_attr_selector"
		c.completeEnrollToToken(t, idName)
		c.assertGrantedServices(t, idName, "test_ext_auth_attr_user_svc")
	})
}

func (c *extAuthContext) enrollToCertUsesMultipleAttrClaims(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		c.overlay.UpdateExtJwtSigner(t, c.workingSigner.name, testutil.ExtJwtSignerSpec{EnrollToCert: true, EnrollAttrSelector: "/groups"})
		idName := "test_ext_auth_multi_attr_selector"
		c.completeEnrollToCert(t, idName)
		c.assertGrantedServices(t, idName, "test_ext_auth_attr_user_svc", "test_ext_auth_attr_admin_svc")
	})
}

func (c *extAuthContext) enrollToTokenUsesMultipleAttrClaims(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		c.overlay.UpdateExtJwtSigner(t, c.workingSigner.name, testutil.ExtJwtSignerSpec{EnrollToToken: true, EnrollAttrSelector: "/groups"})
		idName := "test_ext_auth_token_multi_attr_selector"
		c.completeEnrollToToken(t, idName)
		c.assertGrantedServices(t, idName, "test_ext_auth_attr_user_svc", "test_ext_auth_attr_admin_svc")
	})
}

func (c *extAuthContext) enrollToCertUsesEnrollAuthPolicy(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		c.overlay.UpdateExtJwtSigner(t, c.workingSigner.name, testutil.ExtJwtSignerSpec{EnrollToCert: true, EnrollAuthPolicy: "test_mfa_totp_policy"})
		idName := "test_ext_auth_enroll_auth_policy"
		idEvent := c.completeEnrollToCert(t, idName)

		// TOTP-required policy: the identity is partially-authed, needs MFA
		c.zet.WaitForControllerEvent(t, "disconnected", idName)
		statusEvent := c.zet.WaitForStatusEvent(t)
		provisionedId := findIdentityInStatus(t, statusEvent, idEvent.Id.Identifier)
		require.True(t, provisionedId.MfaNeeded)
		require.False(t, provisionedId.MfaEnabled)
		c.zet.WaitForMfaEvent(t, "enrollment_required", idName)
	})
}

func (c *extAuthContext) enrollToTokenUsesEnrollAuthPolicy(t *testing.T) {
	t.Skip("enroll to token with a TOTP required auth policy hangs on reauth: https://github.com/openziti/ziti-sdk-c/issues/1083")
	testutil.RunWithTimeout(t, func(t *testing.T) {
		c.overlay.UpdateExtJwtSigner(t, c.workingSigner.name, testutil.ExtJwtSignerSpec{EnrollToToken: true, EnrollAuthPolicy: "test_mfa_totp_policy"})
		idName := "test_ext_auth_token_enroll_auth_policy"
		idEvent := c.completeEnrollToToken(t, idName)

		// TOTP-required policy: the identity partial-auths (disconnect), needs MFA, and is not yet enrolled
		c.zet.WaitForControllerEvent(t, "disconnected", idName)
		statusEvent := c.zet.WaitForStatusEvent(t)
		provisionedId := findIdentityInStatus(t, statusEvent, idEvent.Id.Identifier)
		require.True(t, provisionedId.MfaNeeded)
		require.False(t, provisionedId.MfaEnabled)
		c.zet.WaitForMfaEvent(t, "enrollment_required", idName)
	})
}

func (c *extAuthContext) enrollToTokenUsesNameClaimSelector(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		c.overlay.UpdateExtJwtSigner(t, c.workingSigner.name, testutil.ExtJwtSignerSpec{EnrollToToken: true, EnrollNameSelector: "/email"})
		idName := "test_ext_auth_token_name_selector"
		idEvent := c.completeEnrollToToken(t, idName)
		c.assertExpectedIdentityName(t, idEvent, idName)
	})
}

func (c *extAuthContext) bothEnrollFlowsCompleteWhenBothEnabled(t *testing.T) {
	c.overlay.UpdateExtJwtSigner(t, c.workingSigner.name, testutil.ExtJwtSignerSpec{EnrollToCert: true, EnrollToToken: true})
	testutil.RunWithTimeout(t, func(t *testing.T) {
		c.completeEnrollToCert(t, "test_ext_auth_cert_both")
	})
	testutil.RunWithTimeout(t, func(t *testing.T) {
		c.completeEnrollToToken(t, "test_ext_auth_token_both")
	})
}

func (c *extAuthContext) enrollToNoneThenCertRejected(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		idName := "test_ext_auth_none_then_cert"

		enrollToNone := testutil.ExtJwtSignerSpec{}
		c.overlay.UpdateExtJwtSigner(t, c.workingSigner.name, enrollToNone)
		idEvent := testutil.EnrollUrlIdentityToNone(t, c.overlay, c.zet, idName)

		c.overlay.UpdateExtJwtSigner(t, c.workingSigner.name, testutil.ExtJwtSignerSpec{EnrollToCert: true})
		enrollToCertIdentity := testutil.NewUrlIdentityData(idName, c.overlay.ControllerHostPort(), testutil.EnrollModeCert, c.workingSigner.name)
		addResp := c.zet.AddIdentity(t, enrollToCertIdentity)
		addResp.AssertFail(500, "identity exists with the same name")
		testutil.AssertValidUrlEnrolledIdentityFile(t, idEvent.Id.Identifier, testutil.EnrollModeNone)
	})
}

func (c *extAuthContext) enrollToCertThenNoneRejected(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		idName := "test_ext_auth_cert_then_none"

		c.overlay.UpdateExtJwtSigner(t, c.workingSigner.name, testutil.ExtJwtSignerSpec{EnrollToCert: true})
		idEvent := c.completeEnrollToCert(t, idName)

		enrollToNone := testutil.ExtJwtSignerSpec{}
		c.overlay.UpdateExtJwtSigner(t, c.workingSigner.name, enrollToNone)

		enrollToNoneIdentity := testutil.NewUrlIdentityData(idName, c.overlay.ControllerHostPort(), testutil.EnrollModeNone)
		addResp := c.zet.AddIdentity(t, enrollToNoneIdentity)
		addResp.AssertFail(500, "identity exists with the same name")
		testutil.AssertValidUrlEnrolledIdentityFile(t, idEvent.Id.Identifier, testutil.EnrollModeCert)
	})
}

func (c *extAuthContext) enrollToCertThenTokenRejected(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		idName := "test_ext_auth_cert_then_token"

		c.overlay.UpdateExtJwtSigner(t, c.workingSigner.name, testutil.ExtJwtSignerSpec{EnrollToCert: true})
		idEvent := c.completeEnrollToCert(t, idName)

		c.overlay.UpdateExtJwtSigner(t, c.workingSigner.name, testutil.ExtJwtSignerSpec{EnrollToToken: true})
		enrollToTokenIdentity := testutil.NewUrlIdentityData(idName, c.overlay.ControllerHostPort(), testutil.EnrollModeToken, c.workingSigner.name)
		addResp := c.zet.AddIdentity(t, enrollToTokenIdentity)
		addResp.AssertFail(500, "identity exists with the same name")
		testutil.AssertValidUrlEnrolledIdentityFile(t, idEvent.Id.Identifier, testutil.EnrollModeCert)
	})
}

func (c *extAuthContext) enrollToTokenThenCertRejected(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		idName := "test_ext_auth_token_then_cert"

		c.overlay.UpdateExtJwtSigner(t, c.workingSigner.name, testutil.ExtJwtSignerSpec{EnrollToToken: true})
		idEvent := c.completeEnrollToToken(t, idName)

		c.overlay.UpdateExtJwtSigner(t, c.workingSigner.name, testutil.ExtJwtSignerSpec{EnrollToCert: true})
		enrollToCertIdentity := testutil.NewUrlIdentityData(idName, c.overlay.ControllerHostPort(), testutil.EnrollModeCert, c.workingSigner.name)
		addResp := c.zet.AddIdentity(t, enrollToCertIdentity)
		addResp.AssertFail(500, "identity exists with the same name")
		testutil.AssertValidUrlEnrolledIdentityFile(t, idEvent.Id.Identifier, testutil.EnrollModeToken)
	})
}
