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
	c.setupWorkingExtJwtSigner(t)
	return c
}

// setupWorkingExtJwtSigner ensures the working signer exists (find-or-create)
// so either top-level test can run on its own.
func (c *extAuthContext) setupWorkingExtJwtSigner(t *testing.T) {
	c.workingSigner.name = "TestExternalAuth-signer-working"
	if id, found := c.overlay.FindExtJwtSignerId(t, c.workingSigner.name); found {
		c.workingSigner.id = id
		return
	}
	c.workingSigner.id = c.overlay.CreateExtJwtSigner(t, testutil.ExtJwtSignerSpec{
		Name:     c.workingSigner.name,
		Issuer:   c.idp.IssuerURL,
		JWKS:     c.idp.JWKSURI(),
		ClientID: c.idp.ClientIDWorks,
		Claim:    "email",
		Scopes:   []string{"email"},
	})
}

func (c *extAuthContext) setupExtraExtJwtSigners(t *testing.T) {
	c.extraSignerA.name = "TestExternalAuth-signer-extra-a"
	c.extraSignerA.id = c.overlay.CreateExtJwtSigner(t, testutil.ExtJwtSignerSpec{
		Name:     c.extraSignerA.name,
		Issuer:   c.idp.IssuerURL + "-" + c.extraSignerA.name,
		JWKS:     c.idp.JWKSURI() + "-" + c.extraSignerA.name,
		ClientID: c.idp.ClientIDExtraA,
		Claim:    "email",
		Scopes:   []string{"email"},
	})

	c.extraSignerB.name = "TestExternalAuth-signer-extra-b"
	c.extraSignerB.id = c.overlay.CreateExtJwtSigner(t, testutil.ExtJwtSignerSpec{
		Name:     c.extraSignerB.name,
		Issuer:   c.idp.IssuerURL + "-" + c.extraSignerB.name,
		JWKS:     c.idp.JWKSURI() + "-" + c.extraSignerB.name,
		ClientID: c.idp.ClientIDExtraB,
		Claim:    "email",
		Scopes:   []string{"email"},
	})
}

func TestExternalAuthMultipleSigners(t *testing.T) {
	c := newExtAuthContext(t)
	c.setupExtraExtJwtSigners(t)

	t.Run("testEnrollToNoneMultipleSignersDefaultPolicyCompletes", c.testEnrollToNoneMultipleSignersDefaultPolicyCompletes)
	t.Run("testEnrollToNoneMultipleSignersNamedPolicyCompletes", c.testEnrollToNoneMultipleSignersNamedPolicyCompletes)

	_ = c.overlay.DeleteExtJwtSigner(c.extraSignerA.name)
	_ = c.overlay.DeleteExtJwtSigner(c.extraSignerB.name)
}

func TestExternalAuthSingleSigner(t *testing.T) {
	c := newExtAuthContext(t)

	t.Run("testEnrollToNoneCompletes", c.testEnrollToNoneCompletes)
	t.Run("testEnrollToNoneRejectsInvalidProvider", c.testEnrollToNoneRejectsInvalidProvider)
	t.Run("testEnrollToNoneRejectsUnknownControllerIdentity", c.testEnrollToNoneRejectsUnknownControllerIdentity)

	if c.overlay.ZitiMajor < 2 {
		t.Logf("skipping enroll-to-cert/token/both phases: controller is v%d.%d (requires ziti 2.0+)", c.overlay.ZitiMajor, c.overlay.ZitiMinor)
		return
	}

	// Enroll to cert true / enroll to token false
	c.overlay.UpdateExtJwtSigner(t, c.workingSigner.name, testutil.ExtJwtSignerSpec{EnrollToCert: true})
	t.Run("testEnrollToCertCompletes", c.testEnrollToCertCompletes)

	// Enroll to cert false / enroll to token true
	c.overlay.UpdateExtJwtSigner(t, c.workingSigner.name, testutil.ExtJwtSignerSpec{EnrollToToken: true})
	t.Run("testEnrollToTokenCompletes", c.testEnrollToTokenCompletes)

	c.overlay.UpdateExtJwtSigner(t, c.workingSigner.name, testutil.ExtJwtSignerSpec{EnrollToCert: true, EnrollToToken: true})
	t.Run("testBothEnrollFlowsCompleteWhenBothEnabled", c.testBothEnrollFlowsCompleteWhenBothEnabled)

	t.Run("testEnrollToNoneThenCertRejected", c.testEnrollToNoneThenCertRejected)
	t.Run("testEnrollToCertThenNoneRejected", c.testEnrollToCertThenNoneRejected)
	t.Run("testEnrollToCertThenTokenRejected", c.testEnrollToCertThenTokenRejected)
}

func (c *extAuthContext) testEnrollToNoneCompletes(t *testing.T) {
	testutil.RunTestWithTimeout(t, func(t *testing.T) {
		name := testutil.IdentityName(t)
		c.overlay.CreateIdentityWithExternalId(t, name, c.idp.ExternalID, "")
		t.Cleanup(func() { _ = c.overlay.DeleteIdentity(name) })

		identityEvent := c.addEnrollToNoneIdentity(t, name)
		authURL := c.zet.Commands.GetExternalAuthURL(t, identityEvent.Id.Identifier, c.workingSigner.name, c.zet.LogPath())

		c.idp.DriveIdPFlow(t, authURL)

		added := c.zet.Events.WaitForIdentityEvent(t, "added", name)
		require.False(t, added.Id.NeedsExtAuth, "identity:added NeedsExtAuth=%t after IdP login flow, want false", added.Id.NeedsExtAuth)
		require.True(t, added.Id.Active, "identity:added Active=%t after IdP login flow, want true", added.Id.Active)
		testutil.AssertValidUrlEnrolledIdentityFile(t, added.Id.Identifier, testutil.EnrollModeNone)
		t.Logf("identity:added reports NeedsExtAuth=%t Active=%t after IdP login flow", added.Id.NeedsExtAuth, added.Id.Active)
	})
}

func (c *extAuthContext) testEnrollToNoneRejectsInvalidProvider(t *testing.T) {
	testutil.RunTestWithTimeout(t, func(t *testing.T) {
		name := testutil.IdentityName(t)
		c.overlay.CreateIdentityWithExternalId(t, name, c.idp.ExternalID, "")
		t.Cleanup(func() { _ = c.overlay.DeleteIdentity(name) })

		identityEvent := c.addEnrollToNoneIdentity(t, name)

		bogusProvider := c.workingSigner.name + "-bogus"
		t.Logf("sending ExternalAuth with bogus provider %q", bogusProvider)
		resp, err := c.zet.Commands.ExternalAuth(identityEvent.Id.Identifier, bogusProvider)
		require.NoError(t, err, "failed to send ExternalAuth\n%s", c.zet.LogPath())
		require.False(t, resp.Success(), "ExternalAuth should fail for unknown provider %q\n%s", bogusProvider, c.zet.LogPath())
		require.Equal(t, 500, resp.Code, "expected Code=500, got %d", resp.Code)
		require.Contains(t, resp.Error, "invalid provider", "expected invalid-provider error, got %q", resp.Error)
		t.Logf("ExternalAuth failed for invalid provider: code=%d error=%q", resp.Code, resp.Error)
	})
}

func (c *extAuthContext) testEnrollToNoneRejectsUnknownControllerIdentity(t *testing.T) {
	testutil.RunTestWithTimeout(t, func(t *testing.T) {
		name := testutil.IdentityName(t)
		// Deliberately DO NOT create a controller identity with externalId. The
		// OIDC flow at the IdP still succeeds, but the controller rejects login
		// since nothing maps test@example.com to a known identity.

		identityEvent := c.addEnrollToNoneIdentity(t, name)

		authURL := c.zet.Commands.GetExternalAuthURL(t, identityEvent.Id.Identifier, c.workingSigner.name, c.zet.LogPath())

		c.idp.DriveIdPFlow(t, authURL)

		c.zet.Events.WaitForControllerEvent(t, "disconnected", name)
		t.Logf("controller:disconnected")
	})
}

func (c *extAuthContext) testEnrollToNoneMultipleSignersDefaultPolicyCompletes(t *testing.T) {
	testutil.RunTestWithTimeout(t, func(t *testing.T) {
		name := testutil.IdentityName(t)
		c.overlay.CreateIdentityWithExternalId(t, name, c.idp.ExternalID, "")
		t.Cleanup(func() { _ = c.overlay.DeleteIdentity(name) })

		identityEvent := c.addEnrollToNoneIdentity(t, name)
		require.Subset(t, identityEvent.Id.ExtAuthProviders, []string{c.workingSigner.name, c.extraSignerA.name, c.extraSignerB.name}, "identity:needs_ext_login ExtAuthProviders should contain all three signers, got %v", identityEvent.Id.ExtAuthProviders)
		t.Logf("identity:needs_ext_login reports ExtAuthProviders=%v (count=%d)", identityEvent.Id.ExtAuthProviders, len(identityEvent.Id.ExtAuthProviders))

		authURL := c.zet.Commands.GetExternalAuthURL(t, identityEvent.Id.Identifier, c.workingSigner.name, c.zet.LogPath())

		c.idp.DriveIdPFlow(t, authURL)

		added := c.zet.Events.WaitForIdentityEvent(t, "added", name)
		require.False(t, added.Id.NeedsExtAuth, "identity:added NeedsExtAuth=%t after multi-signer IdP login flow, want false", added.Id.NeedsExtAuth)
		require.True(t, added.Id.Active, "identity:added Active=%t after multi-signer IdP login flow, want true", added.Id.Active)
		testutil.AssertValidUrlEnrolledIdentityFile(t, added.Id.Identifier, testutil.EnrollModeNone)
		t.Logf("identity:added reports NeedsExtAuth=%t Active=%t after multi-signer IdP login flow", added.Id.NeedsExtAuth, added.Id.Active)
	})
}

func (c *extAuthContext) testEnrollToNoneMultipleSignersNamedPolicyCompletes(t *testing.T) {
	testutil.RunTestWithTimeout(t, func(t *testing.T) {
		name := testutil.IdentityName(t)

		policyName := name + "-policy"
		c.overlay.CreateAuthPolicyForExtJwt(t, policyName, c.workingSigner.id, c.extraSignerA.id, c.extraSignerB.id)

		c.overlay.CreateIdentityWithExternalId(t, name, c.idp.ExternalID, policyName)

		t.Cleanup(func() {
			_ = c.overlay.DeleteIdentity(name)
			_ = c.overlay.DeleteAuthPolicy(policyName)
		})

		identityEvent := c.addEnrollToNoneIdentity(t, name)
		require.Subset(t, identityEvent.Id.ExtAuthProviders, []string{c.workingSigner.name, c.extraSignerA.name, c.extraSignerB.name}, "identity:needs_ext_login ExtAuthProviders should contain all three signers, got %v", identityEvent.Id.ExtAuthProviders)
		t.Logf("identity:needs_ext_login reports ExtAuthProviders=%v (count=%d)", identityEvent.Id.ExtAuthProviders, len(identityEvent.Id.ExtAuthProviders))

		authURL := c.zet.Commands.GetExternalAuthURL(t, identityEvent.Id.Identifier, c.workingSigner.name, c.zet.LogPath())

		c.idp.DriveIdPFlow(t, authURL)

		added := c.zet.Events.WaitForIdentityEvent(t, "added", name)
		require.False(t, added.Id.NeedsExtAuth, "identity:added NeedsExtAuth=%t after multi-signer IdP login flow, want false", added.Id.NeedsExtAuth)
		require.True(t, added.Id.Active, "identity:added Active=%t after multi-signer IdP login flow, want true", added.Id.Active)
		testutil.AssertValidUrlEnrolledIdentityFile(t, added.Id.Identifier, testutil.EnrollModeNone)
		t.Logf("identity:added reports NeedsExtAuth=%t Active=%t after multi-signer IdP login flow", added.Id.NeedsExtAuth, added.Id.Active)
	})
}

func (c *extAuthContext) addEnrollToNoneIdentity(t *testing.T, name string) testutil.IdentityEvent {
	controllerBase := c.overlay.ControllerHostPort()

	identityData := testutil.AddIdentityData{
		IdentityFilename: name,
		ControllerURL:    &controllerBase,
	}
	addResp := testutil.AddIdentity(t, c.zet.Commands, identityData)
	require.True(t, addResp.Success(), "URL AddIdentity should succeed: error=%q\n%s", addResp.Error, c.zet.LogPath())

	identityEvent := c.zet.Events.WaitForIdentityEvent(t, "needs_ext_login", name)
	require.NotEmpty(t, identityEvent.Id.Identifier, "identity:needs_ext_login Identifier empty")
	require.True(t, identityEvent.Id.NeedsExtAuth, "identity:needs_ext_login NeedsExtAuth=%t, want true", identityEvent.Id.NeedsExtAuth)
	testutil.AssertValidUrlEnrolledIdentityFile(t, identityEvent.Id.Identifier, testutil.EnrollModeNone)
	t.Logf("identity:needs_ext_login Identifier=%s NeedsExtAuth=%t", identityEvent.Id.Identifier, identityEvent.Id.NeedsExtAuth)

	return identityEvent
}

func (c *extAuthContext) testEnrollToCertCompletes(t *testing.T) {
	testutil.RunTestWithTimeout(t, func(t *testing.T) {
		name := testutil.IdentityName(t)
		t.Cleanup(func() { _ = c.overlay.PurgeIdentityByExternalId(c.idp.ExternalID) })

		c.completeEnrollToCert(t, name)
	})
}

// completeEnrollToCert drives a full enroll-to-cert flow for name and returns the
// resulting identifier. The working signer must already have EnrollToCert enabled.
func (c *extAuthContext) completeEnrollToCert(t *testing.T, name string) string {
	controllerBase := c.overlay.ControllerHostPort()
	mode := testutil.EnrollModeCert
	identityData := testutil.AddIdentityData{
		IdentityFilename: name,
		ControllerURL:    &controllerBase,
		EnrollMode:       &mode,
		Provider:         &c.workingSigner.name,
	}
	addResp := testutil.AddIdentity(t, c.zet.Commands, identityData)
	require.True(t, addResp.Success(), "AddIdentity (enroll to cert) should succeed: error=%q\n%s", addResp.Error, c.zet.LogPath())
	require.NotEmpty(t, addResp.Data.URL, "AddIdentity (enroll to cert) response has empty URL")

	c.idp.DriveIdPFlow(t, addResp.Data.URL)

	added := c.zet.Events.WaitForIdentityEvent(t, "added", name)
	require.True(t, added.Id.Active, "identity:added Active=%t after enroll to cert IdP login flow, want true", added.Id.Active)
	require.False(t, added.Id.NeedsExtAuth, "identity:added NeedsExtAuth=%t after enroll to cert IdP login flow, want false", added.Id.NeedsExtAuth)
	testutil.AssertValidUrlEnrolledIdentityFile(t, added.Id.Identifier, testutil.EnrollModeCert)
	t.Logf("identity:added Identifier=%s Active=%t NeedsExtAuth=%t after enroll to cert IdP login flow", added.Id.Identifier, added.Id.Active, added.Id.NeedsExtAuth)
	return added.Id.Identifier
}

func (c *extAuthContext) testEnrollToTokenCompletes(t *testing.T) {
	testutil.RunTestWithTimeout(t, func(t *testing.T) {
		name := testutil.IdentityName(t)
		t.Cleanup(func() { _ = c.overlay.PurgeIdentityByExternalId(c.idp.ExternalID) })

		controllerBase := c.overlay.ControllerHostPort()
		mode := testutil.EnrollModeToken
		identityData := testutil.AddIdentityData{
			IdentityFilename: name,
			ControllerURL:    &controllerBase,
			EnrollMode:       &mode,
			Provider:         &c.workingSigner.name,
		}
		addResp := testutil.AddIdentity(t, c.zet.Commands, identityData)
		require.True(t, addResp.Success(), "AddIdentity (enroll to token) should succeed: error=%q\n%s", addResp.Error, c.zet.LogPath())
		require.NotEmpty(t, addResp.Data.URL, "AddIdentity (enroll to token) response has empty URL")

		c.idp.DriveIdPFlow(t, addResp.Data.URL)

		identityEvent := c.zet.Events.WaitForIdentityEvent(t, "needs_ext_login", name)
		require.True(t, identityEvent.Id.NeedsExtAuth, "identity:needs_ext_login NeedsExtAuth=%t after enroll to token IdP login flow, want true", identityEvent.Id.NeedsExtAuth)
		authURL := c.zet.Commands.GetExternalAuthURL(t, identityEvent.Id.Identifier, c.workingSigner.name, c.zet.LogPath())

		c.idp.DriveIdPFlow(t, authURL)

		added := c.zet.Events.WaitForIdentityEvent(t, "added", name)
		require.True(t, added.Id.Active, "identity:added Active=%t after enroll to token IdP login flow, want true", added.Id.Active)
		require.False(t, added.Id.NeedsExtAuth, "identity:added NeedsExtAuth=%t after enroll to token IdP login flow, want false", added.Id.NeedsExtAuth)
		testutil.AssertValidUrlEnrolledIdentityFile(t, added.Id.Identifier, testutil.EnrollModeToken)
		t.Logf("identity:added Identifier=%s Active=%t NeedsExtAuth=%t after enroll to token IdP login flow", added.Id.Identifier, added.Id.Active, added.Id.NeedsExtAuth)
	})
}

func (c *extAuthContext) testBothEnrollFlowsCompleteWhenBothEnabled(t *testing.T) {
	t.Run("testEnrollToCertCompletes", c.testEnrollToCertCompletes)
	t.Run("testEnrollToTokenCompletes", c.testEnrollToTokenCompletes)
}

func (c *extAuthContext) testEnrollToNoneThenCertRejected(t *testing.T) {
	testutil.RunTestWithTimeout(t, func(t *testing.T) {
		name := testutil.IdentityName(t)

		enrollToNone := testutil.ExtJwtSignerSpec{}
		c.overlay.UpdateExtJwtSigner(t, c.workingSigner.name, enrollToNone)
		identityEvent := c.addEnrollToNoneIdentity(t, name)

		c.overlay.UpdateExtJwtSigner(t, c.workingSigner.name, testutil.ExtJwtSignerSpec{EnrollToCert: true})
		controllerBase := c.overlay.ControllerHostPort()
		mode := testutil.EnrollModeCert
		enrollToCertIdentity := testutil.AddIdentityData{
			IdentityFilename: name,
			ControllerURL:    &controllerBase,
			EnrollMode:       &mode,
			Provider:         &c.workingSigner.name,
		}
		addResp := testutil.AddIdentity(t, c.zet.Commands, enrollToCertIdentity)
		c.assertIdentityExistsSameName(t, addResp)
		testutil.AssertValidUrlEnrolledIdentityFile(t, identityEvent.Id.Identifier, testutil.EnrollModeNone)
	})
}

func (c *extAuthContext) testEnrollToCertThenNoneRejected(t *testing.T) {
	testutil.RunTestWithTimeout(t, func(t *testing.T) {
		name := testutil.IdentityName(t)
		t.Cleanup(func() { _ = c.overlay.PurgeIdentityByExternalId(c.idp.ExternalID) })

		c.overlay.UpdateExtJwtSigner(t, c.workingSigner.name, testutil.ExtJwtSignerSpec{EnrollToCert: true})
		identifier := c.completeEnrollToCert(t, name)

		enrollToNone := testutil.ExtJwtSignerSpec{}
		c.overlay.UpdateExtJwtSigner(t, c.workingSigner.name, enrollToNone)

		controllerBase := c.overlay.ControllerHostPort()
		enrollToNoneIdentity := testutil.AddIdentityData{
			IdentityFilename: name,
			ControllerURL:    &controllerBase,
		}
		addResp := testutil.AddIdentity(t, c.zet.Commands, enrollToNoneIdentity)
		c.assertIdentityExistsSameName(t, addResp)
		testutil.AssertValidUrlEnrolledIdentityFile(t, identifier, testutil.EnrollModeCert)
	})
}

func (c *extAuthContext) testEnrollToCertThenTokenRejected(t *testing.T) {
	testutil.RunTestWithTimeout(t, func(t *testing.T) {
		name := testutil.IdentityName(t)
		t.Cleanup(func() { _ = c.overlay.PurgeIdentityByExternalId(c.idp.ExternalID) })

		c.overlay.UpdateExtJwtSigner(t, c.workingSigner.name, testutil.ExtJwtSignerSpec{EnrollToCert: true})
		identifier := c.completeEnrollToCert(t, name)

		c.overlay.UpdateExtJwtSigner(t, c.workingSigner.name, testutil.ExtJwtSignerSpec{EnrollToToken: true})
		controllerBase := c.overlay.ControllerHostPort()
		mode := testutil.EnrollModeToken
		enrollToTokenIdentity := testutil.AddIdentityData{
			IdentityFilename: name,
			ControllerURL:    &controllerBase,
			EnrollMode:       &mode,
			Provider:         &c.workingSigner.name,
		}
		addResp := testutil.AddIdentity(t, c.zet.Commands, enrollToTokenIdentity)
		c.assertIdentityExistsSameName(t, addResp)
		testutil.AssertValidUrlEnrolledIdentityFile(t, identifier, testutil.EnrollModeCert)
	})
}

// assertIdentityExistsSameName asserts an AddIdentity response was rejected
// because an identity with the same name already exists.
func (c *extAuthContext) assertIdentityExistsSameName(t *testing.T, addResp *testutil.AddIdentityResponse) {
	require.False(t, addResp.Success(), "AddIdentity with an existing name should fail\n%s", c.zet.LogPath())
	require.Equal(t, 500, addResp.Code, "expected Code=500, got %d", addResp.Code)
	require.Contains(t, addResp.Error, "identity exists with the same name", "expected name-collision error, got %q", addResp.Error)
	t.Logf("AddIdentity rejected: code=%d error=%q", addResp.Code, addResp.Error)
}
