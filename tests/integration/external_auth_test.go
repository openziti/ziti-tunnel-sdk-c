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
	"testing"
	"time"

	"github.com/openziti/ziti-tunnel-sdk-c/tests/integration/testutil"
	"github.com/stretchr/testify/require"
)

func RunTestWithTimeout(t *testing.T, name string, f func(t *testing.T)) context.Context {
	d := 30 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Run(name, f)
	t.Cleanup(cancel)
	return ctx
}

func TestExternalAuthEnrolledToNone(t *testing.T) {
	state.overlay.RequireCATrusted(t)
	if state.pkce == nil {
		t.Skip("PKCE IdP is not configured (-pkce-bin not provided)")
	}
	RunTestWithTimeout(t, "testEnrollByUrlCompletes", testEnrollByUrlCompletes)
	RunTestWithTimeout(t, "testInvalidProviderFails", testInvalidProviderFails)
	RunTestWithTimeout(t, "testNoControllerIdentityFails", testNoControllerIdentityFails)
	RunTestWithTimeout(t, "testMultipleSignersWithDefaultPolicyCompletes", testMultipleSignersWithDefaultPolicyCompletes)
	RunTestWithTimeout(t, "testMultipleSignersWithNamedPolicyCompletes", testMultipleSignersWithNamedPolicyCompletes)
}

var ctx = context.Background()

func testEnrollByUrlCompletes(t *testing.T) {
	name := testutil.IdentityName(t)

	signerName := name + "-signer"
	state.overlay.CreateExtJwtSigner(t, ctx, testutil.ExtJwtSignerSpec{
		Name:     signerName,
		Issuer:   state.pkce.IssuerURL,
		JWKS:     state.pkce.JWKSURI(),
		ClientID: state.pkce.ClientIDs[0],
		Claim:    "email",
		Scopes:   []string{"email"},
	})
	state.overlay.CreateIdentityWithExternalId(t, ctx, name, state.pkce.ExternalID, "")

	cleanupCtx := context.Background()
	t.Cleanup(func() {
		_ = state.overlay.DeleteIdentity(cleanupCtx, name)
		_ = state.overlay.DeleteExtJwtSigner(cleanupCtx, signerName)
	})

	needsExt := addIdentityByUrl(t, ctx, name)
	pkce := state.pkce
	s := state.zetClient.Events
	authURL := state.zetClient.Commands.GetExternalAuthURL(t, ctx, needsExt.Id.Identifier, signerName)

	pkce.DrivePKCEFlow(t, ctx, authURL)

	added := s.WaitFor(t, ctx, "identity", "added", name)
	require.False(t, added.Id.NeedsExtAuth, "identity:added NeedsExtAuth=%t after PKCE flow, want false", added.Id.NeedsExtAuth)
	require.True(t, added.Id.Active, "identity:added Active=%t after PKCE flow, want true", added.Id.Active)
	t.Logf("identity:added reports NeedsExtAuth=%t Active=%t after PKCE flow", added.Id.NeedsExtAuth, added.Id.Active)
}

func testInvalidProviderFails(t *testing.T) {
	name := testutil.IdentityName(t)

	signerName := name + "-signer"
	overlay := state.overlay
	pkce := state.pkce
	c := state.zetClient.Commands
	overlay.CreateExtJwtSigner(t, ctx, testutil.ExtJwtSignerSpec{
		Name:     signerName,
		Issuer:   pkce.IssuerURL,
		JWKS:     pkce.JWKSURI(),
		ClientID: pkce.ClientIDs[0],
		Claim:    "email",
		Scopes:   []string{"email"},
	})
	overlay.CreateIdentityWithExternalId(t, ctx, name, pkce.ExternalID, "")

	cleanupCtx := context.Background()
	t.Cleanup(func() {
		_ = overlay.DeleteIdentity(cleanupCtx, name)
		_ = overlay.DeleteExtJwtSigner(cleanupCtx, signerName)
	})

	needsExt := addIdentityByUrl(t, ctx, name)

	bogusProvider := signerName + "-bogus"
	t.Logf("sending ExternalAuth with bogus provider %q", bogusProvider)
	resp, err := c.ExternalAuth(ctx, needsExt.Id.Identifier, bogusProvider)
	require.NoError(t, err, "failed to send ExternalAuth\n%s", state.zetClient.LogPath())
	require.False(t, resp.Success, "ExternalAuth should fail for unknown provider %q\n%s", bogusProvider, state.zetClient.LogPath())
	require.Equal(t, 500, resp.Code, "expected Code=500, got %d", resp.Code)
	require.Contains(t, resp.Error, "invalid provider", "expected invalid-provider error, got %q", resp.Error)
	t.Logf("ExternalAuth failed for invalid provider: code=%d error=%q", resp.Code, resp.Error)
}

func testNoControllerIdentityFails(t *testing.T) {
	name := testutil.IdentityName(t)

	overlay := state.overlay
	pkce := state.pkce
	ev := state.zetClient.Events
	c := state.zetClient.Commands
	signerName := name + "-signer"
	overlay.CreateExtJwtSigner(t, ctx, testutil.ExtJwtSignerSpec{
		Name:     signerName,
		Issuer:   pkce.IssuerURL,
		JWKS:     pkce.JWKSURI(),
		ClientID: pkce.ClientIDs[0],
		Claim:    "email",
		Scopes:   []string{"email"},
	})
	// Deliberately DO NOT create a controller identity with externalId. The
	// OIDC flow at the IdP still succeeds, but the controller rejects login
	// since nothing maps test@example.com to a known identity.
	cleanupCtx := context.Background()
	t.Cleanup(func() {
		_ = overlay.DeleteExtJwtSigner(cleanupCtx, signerName)
	})

	identityEvent := addIdentityByUrl(t, ctx, name)

	authURL := c.GetExternalAuthURL(t, ctx, identityEvent.Id.Identifier, signerName)

	pkce.DrivePKCEFlow(t, ctx, authURL)

	ev.WaitFor(t, ctx, "controller", "disconnected", name)
	t.Logf("controller:disconnected")
}

func testMultipleSignersWithDefaultPolicyCompletes(t *testing.T) {
	overlay := state.overlay
	pkce := state.pkce
	ev := state.zetClient.Events
	c := state.zetClient.Commands
	name := testutil.IdentityName(t)
	jwksURI := pkce.JWKSURI()

	realSignerName := name + "-signer-real"
	signer2Name := name + "-signer-2"
	signer3Name := name + "-signer-3"
	overlay.CreateExtJwtSigner(t, ctx, testutil.ExtJwtSignerSpec{
		Name:     realSignerName,
		Issuer:   pkce.IssuerURL,
		JWKS:     jwksURI,
		ClientID: pkce.ClientIDs[0],
		Claim:    "email",
		Scopes:   []string{"email"},
	})
	overlay.CreateExtJwtSigner(t, ctx, testutil.ExtJwtSignerSpec{
		Name:     signer2Name,
		Issuer:   pkce.IssuerURL + "/" + signer2Name,
		JWKS:     jwksURI,
		ClientID: pkce.ClientIDs[1],
		Claim:    "email",
	})
	overlay.CreateExtJwtSigner(t, ctx, testutil.ExtJwtSignerSpec{
		Name:     signer3Name,
		Issuer:   pkce.IssuerURL + "/" + signer3Name,
		JWKS:     jwksURI,
		ClientID: pkce.ClientIDs[2],
		Claim:    "email",
	})

	overlay.CreateIdentityWithExternalId(t, ctx, name, pkce.ExternalID, "")

	cleanupCtx := context.Background()
	t.Cleanup(func() {
		_ = overlay.DeleteIdentity(cleanupCtx, name)
		_ = overlay.DeleteExtJwtSigner(cleanupCtx, realSignerName)
		_ = overlay.DeleteExtJwtSigner(cleanupCtx, signer2Name)
		_ = overlay.DeleteExtJwtSigner(cleanupCtx, signer3Name)
	})

	needsExt := addIdentityByUrl(t, ctx, name)
	require.Subset(t, needsExt.Id.ExtAuthProviders, []string{realSignerName, signer2Name, signer3Name}, "identity:needs_ext_login ExtAuthProviders should contain all three signers, got %v", needsExt.Id.ExtAuthProviders)
	t.Logf("identity:needs_ext_login reports ExtAuthProviders=%v (count=%d)", needsExt.Id.ExtAuthProviders, len(needsExt.Id.ExtAuthProviders))

	authURL := c.GetExternalAuthURL(t, ctx, needsExt.Id.Identifier, realSignerName)

	pkce.DrivePKCEFlow(t, ctx, authURL)

	added := ev.WaitFor(t, ctx, "identity", "added", name)
	require.False(t, added.Id.NeedsExtAuth, "identity:added NeedsExtAuth=%t after multi-signer PKCE flow, want false", added.Id.NeedsExtAuth)
	require.True(t, added.Id.Active, "identity:added Active=%t after multi-signer PKCE flow, want true", added.Id.Active)
	t.Logf("identity:added reports NeedsExtAuth=%t Active=%t after multi-signer PKCE flow", added.Id.NeedsExtAuth, added.Id.Active)
}

func testMultipleSignersWithNamedPolicyCompletes(t *testing.T) {
	overlay := state.overlay
	pkce := state.pkce
	ev := state.zetClient.Events
	c := state.zetClient.Commands
	name := testutil.IdentityName(t)
	jwksURI := pkce.JWKSURI()

	realSignerName := name + "-signer-real"
	signer2Name := name + "-signer-2"
	signer3Name := name + "-signer-3"
	// Only the real signer is exercised by the auth flow. signer-2 and signer-3
	// just need to exist as distinct providers in the policy; the controller
	// rejects duplicate issuers via a unique index, so they each get a unique
	// sub-path under the PKCE IdP (no traffic ever hits those endpoints).
	realSignerID := overlay.CreateExtJwtSigner(t, ctx, testutil.ExtJwtSignerSpec{
		Name:     realSignerName,
		Issuer:   pkce.IssuerURL,
		JWKS:     jwksURI,
		ClientID: pkce.ClientIDs[0],
		Claim:    "email",
		Scopes:   []string{"email"},
	})
	signer2ID := overlay.CreateExtJwtSigner(t, ctx, testutil.ExtJwtSignerSpec{
		Name:     signer2Name,
		Issuer:   pkce.IssuerURL + "/" + signer2Name,
		JWKS:     jwksURI,
		ClientID: pkce.ClientIDs[1],
		Claim:    "email",
	})
	signer3ID := overlay.CreateExtJwtSigner(t, ctx, testutil.ExtJwtSignerSpec{
		Name:     signer3Name,
		Issuer:   pkce.IssuerURL + "/" + signer3Name,
		JWKS:     jwksURI,
		ClientID: pkce.ClientIDs[2],
		Claim:    "email",
	})

	policyName := name + "-policy"
	overlay.CreateAuthPolicyForExtJwt(t, ctx, policyName, realSignerID, signer2ID, signer3ID)

	overlay.CreateIdentityWithExternalId(t, ctx, name, pkce.ExternalID, policyName)

	cleanupCtx := context.Background()
	t.Cleanup(func() {
		_ = overlay.DeleteIdentity(cleanupCtx, name)
		_ = overlay.DeleteAuthPolicy(cleanupCtx, policyName)
		_ = overlay.DeleteExtJwtSigner(cleanupCtx, realSignerName)
		_ = overlay.DeleteExtJwtSigner(cleanupCtx, signer2Name)
		_ = overlay.DeleteExtJwtSigner(cleanupCtx, signer3Name)
	})

	needsExt := addIdentityByUrl(t, ctx, name)
	require.Subset(t, needsExt.Id.ExtAuthProviders, []string{realSignerName, signer2Name, signer3Name}, "identity:needs_ext_login ExtAuthProviders should contain all three signers, got %v", needsExt.Id.ExtAuthProviders)
	t.Logf("identity:needs_ext_login reports ExtAuthProviders=%v (count=%d)", needsExt.Id.ExtAuthProviders, len(needsExt.Id.ExtAuthProviders))

	authURL := c.GetExternalAuthURL(t, ctx, needsExt.Id.Identifier, realSignerName)

	pkce.DrivePKCEFlow(t, ctx, authURL)

	added := ev.WaitFor(t, ctx, "identity", "added", name)
	require.False(t, added.Id.NeedsExtAuth, "identity:added NeedsExtAuth=%t after multi-signer PKCE flow, want false", added.Id.NeedsExtAuth)
	require.True(t, added.Id.Active, "identity:added Active=%t after multi-signer PKCE flow, want true", added.Id.Active)
	t.Logf("identity:added reports NeedsExtAuth=%t Active=%t after multi-signer PKCE flow", added.Id.NeedsExtAuth, added.Id.Active)
}

func addIdentityByUrl(t *testing.T, ctx context.Context, name string) testutil.Event {
	overlay := state.overlay
	ev := state.zetClient.Events
	c := state.zetClient.Commands
	controllerBase := overlay.ControllerHostPort()

	identityData := testutil.AddIdentityData{
		IdentityFilename: name,
		ControllerURL:    &controllerBase,
	}
	addResp := testutil.AddIdentity(t, ctx, c, identityData)
	require.True(t, addResp.Success, "URL AddIdentity should succeed: error=%q\n%s", addResp.Error, state.zetClient.LogPath())

	needsExt := ev.WaitFor(t, ctx, "identity", "needs_ext_login", name)
	require.NotEmpty(t, needsExt.Id.Identifier, "identity:needs_ext_login Identifier empty")
	require.True(t, needsExt.Id.NeedsExtAuth, "identity:needs_ext_login NeedsExtAuth=%t, want true", needsExt.Id.NeedsExtAuth)
	testutil.AssertValidUrlEnrolledIdentityFile(t, needsExt.Id.Identifier, testutil.EnrollModeNone)
	t.Logf("identity:needs_ext_login Identifier=%s NeedsExtAuth=%t", needsExt.Id.Identifier, needsExt.Id.NeedsExtAuth)

	return needsExt
}
