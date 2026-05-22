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
	overlay      *testutil.Overlay
	pkce         *testutil.PKCE
	zet          *testutil.ZET
	pkceSigner   extJwtSigner
	extraSignerA extJwtSigner
	extraSignerB extJwtSigner
}

func (c *extAuthContext) setupWorkingExtJwtSigner(t *testing.T) {
	c.pkceSigner.name = "TestExternalAuth-signer-pkce"
	c.pkceSigner.id = c.overlay.CreateExtJwtSigner(t, testutil.ExtJwtSignerSpec{
		Name:     c.pkceSigner.name,
		Issuer:   c.pkce.IssuerURL,
		JWKS:     c.pkce.JWKSURI(),
		ClientID: c.pkce.ClientIDWorks,
		Claim:    "email",
		Scopes:   []string{"email"},
	})
}

func (c *extAuthContext) setupExtraExtJwtSigners(t *testing.T) {
	jwksURI := c.pkce.JWKSURI()

	c.extraSignerA.name = "TestExternalAuth-signer-extra-a"
	c.extraSignerA.id = c.overlay.CreateExtJwtSigner(t, testutil.ExtJwtSignerSpec{
		Name:     c.extraSignerA.name,
		Issuer:   c.pkce.IssuerURL + "-" + c.extraSignerA.name,
		JWKS:     jwksURI + "-" + c.extraSignerA.name,
		ClientID: c.pkce.ClientIDExtraA,
		Claim:    "email",
		Scopes:   []string{"email"},
	})

	c.extraSignerB.name = "TestExternalAuth-signer-extra-b"
	c.extraSignerB.id = c.overlay.CreateExtJwtSigner(t, testutil.ExtJwtSignerSpec{
		Name:     c.extraSignerB.name,
		Issuer:   c.pkce.IssuerURL + "-" + c.extraSignerB.name,
		JWKS:     jwksURI + "-" + c.extraSignerB.name,
		ClientID: c.pkce.ClientIDExtraB,
		Claim:    "email",
		Scopes:   []string{"email"},
	})
}

func TestExternalAuthEnrollToNone(t *testing.T) {
	state.overlay.RequireCATrusted(t)
	if state.pkce == nil {
		t.Skip("PKCE IdP is not configured (-pkce-bin not provided)")
	}
	c := &extAuthContext{
		overlay: state.overlay,
		pkce:    state.pkce,
		zet:     state.zetClient,
	}
	c.setupWorkingExtJwtSigner(t)
	c.setupExtraExtJwtSigners(t)
	t.Run("testEnrollToNoneCompletes", c.testEnrollToNoneCompletes)
	t.Run("testEnrollToNoneRejectsInvalidProvider", c.testEnrollToNoneRejectsInvalidProvider)
	t.Run("testEnrollToNoneRejectsUnknownControllerIdentity", c.testEnrollToNoneRejectsUnknownControllerIdentity)
	t.Run("testEnrollToNoneMultipleSignersDefaultPolicyCompletes", c.testEnrollToNoneMultipleSignersDefaultPolicyCompletes)
	t.Run("testEnrollToNoneMultipleSignersNamedPolicyCompletes", c.testEnrollToNoneMultipleSignersNamedPolicyCompletes)
}

func TestExternalAuthEnrollToCert(t *testing.T) {
	state.overlay.RequireCATrusted(t)
	if state.pkce == nil {
		t.Skip("PKCE IdP is not configured (-pkce-bin not provided)")
	}
	if state.overlay.ZitiMajor < 2 {
		t.Skipf("enroll-to-cert requires ziti 2.0+, controller is v%d.%d", state.overlay.ZitiMajor, state.overlay.ZitiMinor)
	}
	c := &extAuthContext{
		overlay: state.overlay,
		pkce:    state.pkce,
		zet:     state.zetClient,
	}
	c.pkceSigner.name = "TestExternalAuth-signer-pkce-cert"
	c.pkceSigner.id = c.overlay.CreateExtJwtSigner(t, testutil.ExtJwtSignerSpec{
		Name:       c.pkceSigner.name,
		Issuer:     c.pkce.IssuerURL,
		JWKS:       c.pkce.JWKSURI(),
		ClientID:   c.pkce.ClientIDWorks,
		Claim:      "email",
		Scopes:     []string{"email"},
		EnrollMode: testutil.EnrollModeCert,
	})
	t.Run("testEnrollToCertCompletes", c.testEnrollToCertCompletes)
}

func (c *extAuthContext) testEnrollToCertCompletes(t *testing.T) {
	testutil.RunTestWithTimeout(t, func(t *testing.T) {
		name := testutil.IdentityName(t)

		controllerBase := c.overlay.ControllerHostPort()
		mode := testutil.EnrollModeCert
		identityData := testutil.AddIdentityData{
			IdentityFilename: name,
			ControllerURL:    &controllerBase,
			EnrollMode:       &mode,
			Provider:         &c.pkceSigner.name,
		}
		addResp := testutil.AddIdentity(t, c.zet.Commands, identityData)
		require.True(t, addResp.Success, "AddIdentity (enroll to cert) should succeed: error=%q\n%s", addResp.Error, c.zet.LogPath())
		authURL := testutil.ParseExtAuthURL(t, addResp)

		c.pkce.DrivePKCEFlow(t, authURL)

		added := c.zet.Events.WaitFor(t, "identity", "added", name)
		require.True(t, added.Id.Active, "identity:added Active=%t after enroll to cert PKCE flow, want true", added.Id.Active)
		require.False(t, added.Id.NeedsExtAuth, "identity:added NeedsExtAuth=%t after enroll to cert PKCE flow, want false", added.Id.NeedsExtAuth)
		testutil.AssertValidUrlEnrolledIdentityFile(t, added.Id.Identifier, testutil.EnrollModeCert)
		t.Logf("identity:added Identifier=%s Active=%t NeedsExtAuth=%t after enroll to cert PKCE flow", added.Id.Identifier, added.Id.Active, added.Id.NeedsExtAuth)
	})
}

func (c *extAuthContext) testEnrollToNoneCompletes(t *testing.T) {
	testutil.RunTestWithTimeout(t, func(t *testing.T) {
		name := testutil.IdentityName(t)
		c.overlay.CreateIdentityWithExternalId(t, name, c.pkce.ExternalID, "")
		t.Cleanup(func() { _ = c.overlay.DeleteIdentity(name) })

		identityEvent := c.addIdentityByUrl(t, name)
		authURL := c.zet.Commands.GetExternalAuthURL(t, identityEvent.Id.Identifier, c.pkceSigner.name, c.zet.LogPath())

		c.pkce.DrivePKCEFlow(t, authURL)

		added := c.zet.Events.WaitFor(t, "identity", "added", name)
		require.False(t, added.Id.NeedsExtAuth, "identity:added NeedsExtAuth=%t after PKCE flow, want false", added.Id.NeedsExtAuth)
		require.True(t, added.Id.Active, "identity:added Active=%t after PKCE flow, want true", added.Id.Active)
		testutil.AssertValidUrlEnrolledIdentityFile(t, added.Id.Identifier, testutil.EnrollModeNone)
		t.Logf("identity:added reports NeedsExtAuth=%t Active=%t after PKCE flow", added.Id.NeedsExtAuth, added.Id.Active)
	})
}

func (c *extAuthContext) testEnrollToNoneRejectsInvalidProvider(t *testing.T) {
	testutil.RunTestWithTimeout(t, func(t *testing.T) {
		name := testutil.IdentityName(t)
		c.overlay.CreateIdentityWithExternalId(t, name, c.pkce.ExternalID, "")
		t.Cleanup(func() { _ = c.overlay.DeleteIdentity(name) })

		identityEvent := c.addIdentityByUrl(t, name)

		bogusProvider := c.pkceSigner.name + "-bogus"
		t.Logf("sending ExternalAuth with bogus provider %q", bogusProvider)
		resp, err := c.zet.Commands.ExternalAuth(identityEvent.Id.Identifier, bogusProvider)
		require.NoError(t, err, "failed to send ExternalAuth\n%s", c.zet.LogPath())
		require.False(t, resp.Success, "ExternalAuth should fail for unknown provider %q\n%s", bogusProvider, c.zet.LogPath())
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

		identityEvent := c.addIdentityByUrl(t, name)

		authURL := c.zet.Commands.GetExternalAuthURL(t, identityEvent.Id.Identifier, c.pkceSigner.name, c.zet.LogPath())

		c.pkce.DrivePKCEFlow(t, authURL)

		c.zet.Events.WaitFor(t, "controller", "disconnected", name)
		t.Logf("controller:disconnected")
	})
}

func (c *extAuthContext) testEnrollToNoneMultipleSignersDefaultPolicyCompletes(t *testing.T) {
	testutil.RunTestWithTimeout(t, func(t *testing.T) {
		name := testutil.IdentityName(t)
		c.overlay.CreateIdentityWithExternalId(t, name, c.pkce.ExternalID, "")
		t.Cleanup(func() { _ = c.overlay.DeleteIdentity(name) })

		identityEvent := c.addIdentityByUrl(t, name)
		require.Subset(t, identityEvent.Id.ExtAuthProviders, []string{c.pkceSigner.name, c.extraSignerA.name, c.extraSignerB.name}, "identity:needs_ext_login ExtAuthProviders should contain all three signers, got %v", identityEvent.Id.ExtAuthProviders)
		t.Logf("identity:needs_ext_login reports ExtAuthProviders=%v (count=%d)", identityEvent.Id.ExtAuthProviders, len(identityEvent.Id.ExtAuthProviders))

		authURL := c.zet.Commands.GetExternalAuthURL(t, identityEvent.Id.Identifier, c.pkceSigner.name, c.zet.LogPath())

		c.pkce.DrivePKCEFlow(t, authURL)

		added := c.zet.Events.WaitFor(t, "identity", "added", name)
		require.False(t, added.Id.NeedsExtAuth, "identity:added NeedsExtAuth=%t after multi-signer PKCE flow, want false", added.Id.NeedsExtAuth)
		require.True(t, added.Id.Active, "identity:added Active=%t after multi-signer PKCE flow, want true", added.Id.Active)
		testutil.AssertValidUrlEnrolledIdentityFile(t, added.Id.Identifier, testutil.EnrollModeNone)
		t.Logf("identity:added reports NeedsExtAuth=%t Active=%t after multi-signer PKCE flow", added.Id.NeedsExtAuth, added.Id.Active)
	})
}

func (c *extAuthContext) testEnrollToNoneMultipleSignersNamedPolicyCompletes(t *testing.T) {
	testutil.RunTestWithTimeout(t, func(t *testing.T) {
		name := testutil.IdentityName(t)

		policyName := name + "-policy"
		c.overlay.CreateAuthPolicyForExtJwt(t, policyName, c.pkceSigner.id, c.extraSignerA.id, c.extraSignerB.id)

		c.overlay.CreateIdentityWithExternalId(t, name, c.pkce.ExternalID, policyName)

		t.Cleanup(func() {
			_ = c.overlay.DeleteIdentity(name)
			_ = c.overlay.DeleteAuthPolicy(policyName)
		})

		identityEvent := c.addIdentityByUrl(t, name)
		require.Subset(t, identityEvent.Id.ExtAuthProviders, []string{c.pkceSigner.name, c.extraSignerA.name, c.extraSignerB.name}, "identity:needs_ext_login ExtAuthProviders should contain all three signers, got %v", identityEvent.Id.ExtAuthProviders)
		t.Logf("identity:needs_ext_login reports ExtAuthProviders=%v (count=%d)", identityEvent.Id.ExtAuthProviders, len(identityEvent.Id.ExtAuthProviders))

		authURL := c.zet.Commands.GetExternalAuthURL(t, identityEvent.Id.Identifier, c.pkceSigner.name, c.zet.LogPath())

		c.pkce.DrivePKCEFlow(t, authURL)

		added := c.zet.Events.WaitFor(t, "identity", "added", name)
		require.False(t, added.Id.NeedsExtAuth, "identity:added NeedsExtAuth=%t after multi-signer PKCE flow, want false", added.Id.NeedsExtAuth)
		require.True(t, added.Id.Active, "identity:added Active=%t after multi-signer PKCE flow, want true", added.Id.Active)
		testutil.AssertValidUrlEnrolledIdentityFile(t, added.Id.Identifier, testutil.EnrollModeNone)
		t.Logf("identity:added reports NeedsExtAuth=%t Active=%t after multi-signer PKCE flow", added.Id.NeedsExtAuth, added.Id.Active)
	})
}

func (c *extAuthContext) addIdentityByUrl(t *testing.T, name string) testutil.Event {
	controllerBase := c.overlay.ControllerHostPort()

	identityData := testutil.AddIdentityData{
		IdentityFilename: name,
		ControllerURL:    &controllerBase,
	}
	addResp := testutil.AddIdentity(t, c.zet.Commands, identityData)
	require.True(t, addResp.Success, "URL AddIdentity should succeed: error=%q\n%s", addResp.Error, c.zet.LogPath())

	identityEvent := c.zet.Events.WaitFor(t, "identity", "needs_ext_login", name)
	require.NotEmpty(t, identityEvent.Id.Identifier, "identity:needs_ext_login Identifier empty")
	require.True(t, identityEvent.Id.NeedsExtAuth, "identity:needs_ext_login NeedsExtAuth=%t, want true", identityEvent.Id.NeedsExtAuth)
	testutil.AssertValidUrlEnrolledIdentityFile(t, identityEvent.Id.Identifier, testutil.EnrollModeNone)
	t.Logf("identity:needs_ext_login Identifier=%s NeedsExtAuth=%t", identityEvent.Id.Identifier, identityEvent.Id.NeedsExtAuth)

	return identityEvent
}
