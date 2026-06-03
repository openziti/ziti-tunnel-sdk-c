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
	"strings"
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
	c.extraSignerA.name = "TestExternalAuth-signer-extra-a"
	c.extraSignerA.id = c.overlay.CreateExtJwtSigner(t, testutil.ExtJwtSignerSpec{
		Name:     c.extraSignerA.name,
		Issuer:   c.idp.IssuerURL + "-" + c.extraSignerA.name,
		JWKS:     c.idp.JWKSURI() + "-" + c.extraSignerA.name,
		ClientID: c.idp.ClientIDExtraA,
		Audience: c.idp.Audience,
		Claim:    "email",
		Scopes:   strings.Fields(c.idp.Scopes),
	})

	c.extraSignerB.name = "TestExternalAuth-signer-extra-b"
	c.extraSignerB.id = c.overlay.CreateExtJwtSigner(t, testutil.ExtJwtSignerSpec{
		Name:     c.extraSignerB.name,
		Issuer:   c.idp.IssuerURL + "-" + c.extraSignerB.name,
		JWKS:     c.idp.JWKSURI() + "-" + c.extraSignerB.name,
		ClientID: c.idp.ClientIDExtraB,
		Audience: c.idp.Audience,
		Claim:    "email",
		Scopes:   strings.Fields(c.idp.Scopes),
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

	// Enroll to cert true / enroll to token false
	c.overlay.UpdateExtJwtSigner(t, c.workingSigner.name, testutil.ExtJwtSignerSpec{EnrollToCert: true})
	t.Run("enrollToCertCompletes", c.enrollToCertCompletes)

	// Enroll to cert false / enroll to token true
	c.overlay.UpdateExtJwtSigner(t, c.workingSigner.name, testutil.ExtJwtSignerSpec{EnrollToToken: true})
	t.Run("enrollToTokenCompletes", c.enrollToTokenCompletes)

	c.overlay.UpdateExtJwtSigner(t, c.workingSigner.name, testutil.ExtJwtSignerSpec{EnrollToCert: true, EnrollToToken: true})
	t.Run("bothEnrollFlowsCompleteWhenBothEnabled", c.bothEnrollFlowsCompleteWhenBothEnabled)

	t.Run("enrollToNoneThenCertRejected", c.enrollToNoneThenCertRejected)
	t.Run("enrollToCertThenNoneRejected", c.enrollToCertThenNoneRejected)
	t.Run("enrollToCertThenTokenRejected", c.enrollToCertThenTokenRejected)
	t.Run("enrollToTokenThenCertRejected", c.enrollToTokenThenCertRejected)
}

func (c *extAuthContext) enrollToNoneCompletes(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		name := testutil.IdentityName(t)
		c.overlay.CreateIdentityWithExternalId(t, name, c.idp.ExternalID, "")
		t.Cleanup(func() { _ = c.overlay.DeleteIdentity(name) })

		identityEvent := testutil.EnrollUrlIdentityToNone(t, c.overlay, c.zet, name)
		authURL := c.zet.GetExternalAuthURL(t, identityEvent.Id.Identifier, c.workingSigner.name, c.zet.LogPath())

		c.idp.DriveIdPFlow(t, authURL)

		added := c.zet.WaitForIdentityEvent(t, "added", name)
		require.False(t, added.Id.NeedsExtAuth, "identity:added NeedsExtAuth=%t after IdP login flow", added.Id.NeedsExtAuth)
		require.True(t, added.Id.Active, "identity:added Active=%t after IdP login flow", added.Id.Active)
		testutil.AssertValidUrlEnrolledIdentityFile(t, added.Id.Identifier, testutil.EnrollModeNone)
	})
}

func (c *extAuthContext) enrollToNoneRejectsInvalidProvider(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		name := testutil.IdentityName(t)
		c.overlay.CreateIdentityWithExternalId(t, name, c.idp.ExternalID, "")
		t.Cleanup(func() { _ = c.overlay.DeleteIdentity(name) })

		identityEvent := testutil.EnrollUrlIdentityToNone(t, c.overlay, c.zet, name)

		bogusProvider := c.workingSigner.name + "-bogus"
		t.Logf("sending ExternalAuth with bogus provider %q", bogusProvider)
		resp, err := c.zet.ExternalAuth(identityEvent.Id.Identifier, bogusProvider)
		require.NoError(t, err, "failed to send ExternalAuth\n%s", c.zet.LogPath())
		require.False(t, resp.Success(), "ExternalAuth should fail for unknown provider %q\n%s", bogusProvider, c.zet.LogPath())
		require.Equal(t, 500, resp.Code, "expected Code=500, got %d", resp.Code)
		require.Contains(t, resp.Error, "invalid provider", "expected invalid-provider error, got %q", resp.Error)
	})
}

func (c *extAuthContext) enrollToNoneRejectsUnknownControllerIdentity(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		name := testutil.IdentityName(t)
		// Deliberately DO NOT create a controller identity with externalId. The
		// OIDC flow at the IdP still succeeds, but the controller rejects login
		// since nothing maps test@example.com to a known identity.

		identityEvent := testutil.EnrollUrlIdentityToNone(t, c.overlay, c.zet, name)

		authURL := c.zet.GetExternalAuthURL(t, identityEvent.Id.Identifier, c.workingSigner.name, c.zet.LogPath())

		c.idp.DriveIdPFlow(t, authURL)

		c.zet.WaitForControllerEvent(t, "disconnected", name)
	})
}

func (c *extAuthContext) enrollToNoneMultipleSignersDefaultPolicyCompletes(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		name := testutil.IdentityName(t)
		c.overlay.CreateIdentityWithExternalId(t, name, c.idp.ExternalID, "")
		t.Cleanup(func() { _ = c.overlay.DeleteIdentity(name) })

		identityEvent := testutil.EnrollUrlIdentityToNone(t, c.overlay, c.zet, name)
		require.Subset(t, identityEvent.Id.ExtAuthProviders, []string{c.workingSigner.name, c.extraSignerA.name, c.extraSignerB.name}, "identity:needs_ext_login ExtAuthProviders should contain all three signers, got %v", identityEvent.Id.ExtAuthProviders)

		authURL := c.zet.GetExternalAuthURL(t, identityEvent.Id.Identifier, c.workingSigner.name, c.zet.LogPath())

		c.idp.DriveIdPFlow(t, authURL)

		added := c.zet.WaitForIdentityEvent(t, "added", name)
		require.False(t, added.Id.NeedsExtAuth, "identity:added NeedsExtAuth=%t after multi-signer IdP login flow", added.Id.NeedsExtAuth)
		require.True(t, added.Id.Active, "identity:added Active=%t after multi-signer IdP login flow", added.Id.Active)
		testutil.AssertValidUrlEnrolledIdentityFile(t, added.Id.Identifier, testutil.EnrollModeNone)
	})
}

func (c *extAuthContext) enrollToNoneMultipleSignersNamedPolicyCompletes(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		name := testutil.IdentityName(t)

		policyName := name + "-policy"
		c.overlay.CreateAuthPolicyForExtJwt(t, policyName, c.workingSigner.id, c.extraSignerA.id, c.extraSignerB.id)

		c.overlay.CreateIdentityWithExternalId(t, name, c.idp.ExternalID, policyName)

		t.Cleanup(func() {
			_ = c.overlay.DeleteIdentity(name)
			_ = c.overlay.DeleteAuthPolicy(policyName)
		})

		identityEvent := testutil.EnrollUrlIdentityToNone(t, c.overlay, c.zet, name)
		require.Subset(t, identityEvent.Id.ExtAuthProviders, []string{c.workingSigner.name, c.extraSignerA.name, c.extraSignerB.name}, "identity:needs_ext_login ExtAuthProviders should contain all three signers, got %v", identityEvent.Id.ExtAuthProviders)

		authURL := c.zet.GetExternalAuthURL(t, identityEvent.Id.Identifier, c.workingSigner.name, c.zet.LogPath())

		c.idp.DriveIdPFlow(t, authURL)

		added := c.zet.WaitForIdentityEvent(t, "added", name)
		require.False(t, added.Id.NeedsExtAuth, "identity:added NeedsExtAuth=%t after multi-signer IdP login flow", added.Id.NeedsExtAuth)
		require.True(t, added.Id.Active, "identity:added Active=%t after multi-signer IdP login flow", added.Id.Active)
		testutil.AssertValidUrlEnrolledIdentityFile(t, added.Id.Identifier, testutil.EnrollModeNone)
	})
}

func (c *extAuthContext) enrollToCertCompletes(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		name := testutil.IdentityName(t)
		t.Cleanup(c.deleteIdentityByExternalId)

		c.completeEnrollToCert(t, name)
	})
}

func (c *extAuthContext) createIdentityData(name string, mode testutil.EnrollMode) testutil.AddIdentityData {
	controllerBase := c.overlay.ControllerHostPort()
	return testutil.AddIdentityData{
		IdentityFilename: name,
		ControllerURL:    &controllerBase,
		EnrollMode:       &mode,
		Provider:         &c.workingSigner.name,
	}
}

func (c *extAuthContext) deleteIdentityByExternalId() {
	_ = c.overlay.PurgeIdentityByExternalId(c.idp.ExternalID)
}

// beginEnrollment sends AddIdentity and returns the enrollment URL the IdP flow
// continues at, asserting the response succeeded and carried a URL.
func (c *extAuthContext) beginEnrollment(t *testing.T, identityData testutil.AddIdentityData) string {
	addResp := testutil.AddIdentity(t, c.zet.CommandsClient, identityData)
	require.True(t, addResp.Success(), "AddIdentity should succeed: error=%q\n%s", addResp.Error, c.zet.LogPath())
	require.NotEmpty(t, addResp.Data.URL, "AddIdentity response has empty URL")
	return addResp.Data.URL
}

// completeEnrollToCert drives a full enroll-to-cert flow for name and returns the
// resulting identifier. The working signer must already have EnrollToCert enabled.
func (c *extAuthContext) completeEnrollToCert(t *testing.T, name string) string {
	identityData := c.createIdentityData(name, testutil.EnrollModeCert)
	authURL := c.beginEnrollment(t, identityData)

	c.idp.DriveIdPFlow(t, authURL)

	added := c.zet.WaitForIdentityEvent(t, "added", name)
	require.True(t, added.Id.Active, "identity:added Active=%t after enroll to cert IdP login flow", added.Id.Active)
	require.False(t, added.Id.NeedsExtAuth, "identity:added NeedsExtAuth=%t after enroll to cert IdP login flow", added.Id.NeedsExtAuth)
	testutil.AssertValidUrlEnrolledIdentityFile(t, added.Id.Identifier, testutil.EnrollModeCert)
	return added.Id.Identifier
}

func (c *extAuthContext) enrollToTokenCompletes(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		name := testutil.IdentityName(t)
		t.Cleanup(c.deleteIdentityByExternalId)

		c.completeEnrollToToken(t, name)
	})
}

// completeEnrollToToken drives a full enroll-to-token flow for name and returns the
// resulting identifier. The working signer must already have EnrollToToken enabled.
func (c *extAuthContext) completeEnrollToToken(t *testing.T, name string) string {
	identityData := c.createIdentityData(name, testutil.EnrollModeToken)
	authURL := c.beginEnrollment(t, identityData)

	c.idp.DriveIdPFlow(t, authURL)

	identityEvent := c.zet.WaitForIdentityEvent(t, "needs_ext_login", name)
	require.True(t, identityEvent.Id.NeedsExtAuth, "identity:needs_ext_login NeedsExtAuth=%t after enroll to token IdP login flow", identityEvent.Id.NeedsExtAuth)
	authURL = c.zet.GetExternalAuthURL(t, identityEvent.Id.Identifier, c.workingSigner.name, c.zet.LogPath())

	c.idp.DriveIdPFlow(t, authURL)

	added := c.zet.WaitForIdentityEvent(t, "added", name)
	require.True(t, added.Id.Active, "identity:added Active=%t after enroll to token IdP login flow", added.Id.Active)
	require.False(t, added.Id.NeedsExtAuth, "identity:added NeedsExtAuth=%t after enroll to token IdP login flow", added.Id.NeedsExtAuth)
	testutil.AssertValidUrlEnrolledIdentityFile(t, added.Id.Identifier, testutil.EnrollModeToken)
	return added.Id.Identifier
}

func (c *extAuthContext) bothEnrollFlowsCompleteWhenBothEnabled(t *testing.T) {
	t.Run("enrollToCertCompletes", c.enrollToCertCompletes)
	t.Run("enrollToTokenCompletes", c.enrollToTokenCompletes)
}

func (c *extAuthContext) enrollToNoneThenCertRejected(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		name := testutil.IdentityName(t)

		enrollToNone := testutil.ExtJwtSignerSpec{}
		c.overlay.UpdateExtJwtSigner(t, c.workingSigner.name, enrollToNone)
		identityEvent := testutil.EnrollUrlIdentityToNone(t, c.overlay, c.zet, name)

		c.overlay.UpdateExtJwtSigner(t, c.workingSigner.name, testutil.ExtJwtSignerSpec{EnrollToCert: true})
		enrollToCertIdentity := c.createIdentityData(name, testutil.EnrollModeCert)
		addResp := testutil.AddIdentity(t, c.zet.CommandsClient, enrollToCertIdentity)
		c.assertIdentityExistsSameName(t, addResp)
		testutil.AssertValidUrlEnrolledIdentityFile(t, identityEvent.Id.Identifier, testutil.EnrollModeNone)
	})
}

func (c *extAuthContext) enrollToCertThenNoneRejected(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		name := testutil.IdentityName(t)
		t.Cleanup(c.deleteIdentityByExternalId)

		c.overlay.UpdateExtJwtSigner(t, c.workingSigner.name, testutil.ExtJwtSignerSpec{EnrollToCert: true})
		identifier := c.completeEnrollToCert(t, name)

		enrollToNone := testutil.ExtJwtSignerSpec{}
		c.overlay.UpdateExtJwtSigner(t, c.workingSigner.name, enrollToNone)

		controllerBase := c.overlay.ControllerHostPort()
		enrollToNoneIdentity := testutil.AddIdentityData{
			IdentityFilename: name,
			ControllerURL:    &controllerBase,
		}
		addResp := testutil.AddIdentity(t, c.zet.CommandsClient, enrollToNoneIdentity)
		c.assertIdentityExistsSameName(t, addResp)
		testutil.AssertValidUrlEnrolledIdentityFile(t, identifier, testutil.EnrollModeCert)
	})
}

func (c *extAuthContext) enrollToCertThenTokenRejected(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		name := testutil.IdentityName(t)
		t.Cleanup(c.deleteIdentityByExternalId)

		c.overlay.UpdateExtJwtSigner(t, c.workingSigner.name, testutil.ExtJwtSignerSpec{EnrollToCert: true})
		identifier := c.completeEnrollToCert(t, name)

		c.overlay.UpdateExtJwtSigner(t, c.workingSigner.name, testutil.ExtJwtSignerSpec{EnrollToToken: true})
		enrollToTokenIdentity := c.createIdentityData(name, testutil.EnrollModeToken)
		addResp := testutil.AddIdentity(t, c.zet.CommandsClient, enrollToTokenIdentity)
		c.assertIdentityExistsSameName(t, addResp)
		testutil.AssertValidUrlEnrolledIdentityFile(t, identifier, testutil.EnrollModeCert)
	})
}

func (c *extAuthContext) enrollToTokenThenCertRejected(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		name := testutil.IdentityName(t)
		t.Cleanup(c.deleteIdentityByExternalId)

		c.overlay.UpdateExtJwtSigner(t, c.workingSigner.name, testutil.ExtJwtSignerSpec{EnrollToToken: true})
		identifier := c.completeEnrollToToken(t, name)

		c.overlay.UpdateExtJwtSigner(t, c.workingSigner.name, testutil.ExtJwtSignerSpec{EnrollToCert: true})
		enrollToCertIdentity := c.createIdentityData(name, testutil.EnrollModeCert)
		addResp := testutil.AddIdentity(t, c.zet.CommandsClient, enrollToCertIdentity)
		c.assertIdentityExistsSameName(t, addResp)
		testutil.AssertValidUrlEnrolledIdentityFile(t, identifier, testutil.EnrollModeToken)
	})
}

// assertIdentityExistsSameName asserts an AddIdentity response was rejected
// because an identity with the same name already exists.
func (c *extAuthContext) assertIdentityExistsSameName(t *testing.T, addResp *testutil.AddIdentityResponse) {
	require.False(t, addResp.Success(), "AddIdentity with an existing name should fail\n%s", c.zet.LogPath())
	require.Equal(t, 500, addResp.Code, "expected Code=500, got %d", addResp.Code)
	require.Contains(t, addResp.Error, "identity exists with the same name", "expected name-collision error, got %q", addResp.Error)
}
