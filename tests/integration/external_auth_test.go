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

type extAuthState struct {
	events *testutil.EventClient
	client *testutil.IPCClient
}

func TestExternalAuthEnrolledToNone(t *testing.T) {
	overlay.RequireCATrusted(t)
	if pkce == nil {
		t.Skip("PKCE IdP is not configured (-pkce-bin not provided)")
	}
	ctx := context.Background()
	state := &extAuthState{
		events: testutil.SubscribeEvents(t, ctx, zet),
		client: testutil.OpenCommandPipe(t, ctx, zet),
	}
	t.Run("enrollByUrlCompletes", state.testEnrollByUrlCompletes)
	t.Run("invalidProviderFails", state.testInvalidProviderFails)
	t.Run("noControllerIdentityFails", state.testNoControllerIdentityFails)
	t.Run("multipleSignersWithDefaultPolicyCompletes", state.testMultipleSignersWithDefaultPolicyCompletes)
	t.Run("multipleSignersWithNamedPolicyCompletes", state.testMultipleSignersWithNamedPolicyCompletes)
}

func (s *extAuthState) testEnrollByUrlCompletes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	name := testutil.IdentityName(t)

	signerName := name + "-signer"
	overlay.CreateExtJwtSigner(t, ctx, testutil.ExtJwtSignerSpec{
		Name:     signerName,
		Issuer:   pkce.IssuerURL,
		JWKS:     pkce.JWKSURI(),
		ClientID: pkce.ClientIDs[0],
		Claim:    "email",
		Scopes:   []string{"email"},
	})
	t.Logf("creating controller identity %q with externalId=%q bound to default auth policy", name, pkce.ExternalID)
	require.NoError(t, overlay.CreateIdentityWithExternalId(ctx, name, pkce.ExternalID, ""), "create controller identity with externalId=PKCE user email")
	t.Logf("controller identity %q created", name)

	cleanupCtx := context.Background()
	t.Cleanup(func() {
		_ = overlay.DeleteIdentity(cleanupCtx, name)
		_ = overlay.DeleteExtJwtSigner(cleanupCtx, signerName)
	})

	needsExt := s.urlEnrollForExtAuth(t, ctx, name)

	authURL := s.client.GetExternalAuthURL(t, ctx, needsExt.Id.Identifier, signerName)

	testutil.DrivePKCEFlow(t, ctx, authURL, pkce.IssuerURL, pkce.Email, pkce.Password)

	added := s.events.WaitFor(t, ctx, "identity", "added", name)
	require.False(t, added.Id.NeedsExtAuth, "identity:added NeedsExtAuth=%t after PKCE flow, want false", added.Id.NeedsExtAuth)
	require.True(t, added.Id.Active, "identity:added Active=%t after PKCE flow, want true", added.Id.Active)
	t.Logf("identity:added reports NeedsExtAuth=%t Active=%t after PKCE flow", added.Id.NeedsExtAuth, added.Id.Active)
}

func (s *extAuthState) testInvalidProviderFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	name := testutil.IdentityName(t)

	signerName := name + "-signer"
	overlay.CreateExtJwtSigner(t, ctx, testutil.ExtJwtSignerSpec{
		Name:     signerName,
		Issuer:   pkce.IssuerURL,
		JWKS:     pkce.JWKSURI(),
		ClientID: pkce.ClientIDs[0],
		Claim:    "email",
		Scopes:   []string{"email"},
	})
	t.Logf("creating controller identity %q with externalId=%q bound to default auth policy", name, pkce.ExternalID)
	require.NoError(t, overlay.CreateIdentityWithExternalId(ctx, name, pkce.ExternalID, ""), "create controller identity with externalId=PKCE user email")
	t.Logf("controller identity %q created", name)

	cleanupCtx := context.Background()
	t.Cleanup(func() {
		_ = overlay.DeleteIdentity(cleanupCtx, name)
		_ = overlay.DeleteExtJwtSigner(cleanupCtx, signerName)
	})

	needsExt := s.urlEnrollForExtAuth(t, ctx, name)

	bogusProvider := signerName + "-bogus"
	t.Logf("sending ExternalAuth with bogus provider %q", bogusProvider)
	resp, err := s.client.ExternalAuth(ctx, needsExt.Id.Identifier, bogusProvider)
	require.NoError(t, err, "failed to send ExternalAuth\n%s", zet.Logs())
	require.False(t, resp.Success, "ExternalAuth should fail for unknown provider %q\n%s", bogusProvider, zet.Logs())
	require.Equal(t, 500, resp.Code, "expected Code=500, got %d", resp.Code)
	require.Contains(t, resp.Error, "invalid provider", "expected invalid-provider error, got %q", resp.Error)
	t.Logf("ExternalAuth failed for invalid provider: code=%d error=%q", resp.Code, resp.Error)
}

func (s *extAuthState) testNoControllerIdentityFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	name := testutil.IdentityName(t)

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
	t.Logf("skipping controller identity creation on purpose (controller should reject because externalId=%q is unmapped)", pkce.ExternalID)

	cleanupCtx := context.Background()
	t.Cleanup(func() {
		_ = overlay.DeleteExtJwtSigner(cleanupCtx, signerName)
	})

	needsExt := s.urlEnrollForExtAuth(t, ctx, name)

	authURL := s.client.GetExternalAuthURL(t, ctx, needsExt.Id.Identifier, signerName)

	testutil.DrivePKCEFlow(t, ctx, authURL, pkce.IssuerURL, pkce.Email, pkce.Password)

	s.events.WaitFor(t, ctx, "controller", "disconnected", name)
	t.Logf("controller:disconnected")
}

func (s *extAuthState) testMultipleSignersWithDefaultPolicyCompletes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

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

	t.Logf("creating controller identity %q with externalId=%q bound to default auth policy", name, pkce.ExternalID)
	require.NoError(t, overlay.CreateIdentityWithExternalId(ctx, name, pkce.ExternalID, ""), "create controller identity with externalId=PKCE user email")
	t.Logf("controller identity %q created", name)

	cleanupCtx := context.Background()
	t.Cleanup(func() {
		_ = overlay.DeleteIdentity(cleanupCtx, name)
		_ = overlay.DeleteExtJwtSigner(cleanupCtx, realSignerName)
		_ = overlay.DeleteExtJwtSigner(cleanupCtx, signer2Name)
		_ = overlay.DeleteExtJwtSigner(cleanupCtx, signer3Name)
	})

	needsExt := s.urlEnrollForExtAuth(t, ctx, name)
	require.Subset(t, needsExt.Id.ExtAuthProviders, []string{realSignerName, signer2Name, signer3Name}, "identity:needs_ext_login ExtAuthProviders should contain all three signers, got %v", needsExt.Id.ExtAuthProviders)
	t.Logf("identity:needs_ext_login reports ExtAuthProviders=%v (count=%d)", needsExt.Id.ExtAuthProviders, len(needsExt.Id.ExtAuthProviders))

	authURL := s.client.GetExternalAuthURL(t, ctx, needsExt.Id.Identifier, realSignerName)

	testutil.DrivePKCEFlow(t, ctx, authURL, pkce.IssuerURL, pkce.Email, pkce.Password)

	added := s.events.WaitFor(t, ctx, "identity", "added", name)
	require.False(t, added.Id.NeedsExtAuth, "identity:added NeedsExtAuth=%t after multi-signer PKCE flow, want false", added.Id.NeedsExtAuth)
	require.True(t, added.Id.Active, "identity:added Active=%t after multi-signer PKCE flow, want true", added.Id.Active)
	t.Logf("identity:added reports NeedsExtAuth=%t Active=%t after multi-signer PKCE flow", added.Id.NeedsExtAuth, added.Id.Active)
}

func (s *extAuthState) testMultipleSignersWithNamedPolicyCompletes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

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
	t.Logf("creating multi-signer auth policy %q binding all three signers", policyName)
	require.NoError(t, overlay.CreateAuthPolicyForExtJwt(ctx, policyName, realSignerID, signer2ID, signer3ID), "create multi-signer auth policy")
	t.Logf("auth policy %q created", policyName)

	t.Logf("creating controller identity %q with externalId=%q bound to policy %q", name, pkce.ExternalID, policyName)
	require.NoError(t, overlay.CreateIdentityWithExternalId(ctx, name, pkce.ExternalID, policyName), "create controller identity with externalId=PKCE user email")
	t.Logf("controller identity %q created", name)

	cleanupCtx := context.Background()
	t.Cleanup(func() {
		_ = overlay.DeleteIdentity(cleanupCtx, name)
		_ = overlay.DeleteAuthPolicy(cleanupCtx, policyName)
		_ = overlay.DeleteExtJwtSigner(cleanupCtx, realSignerName)
		_ = overlay.DeleteExtJwtSigner(cleanupCtx, signer2Name)
		_ = overlay.DeleteExtJwtSigner(cleanupCtx, signer3Name)
	})

	needsExt := s.urlEnrollForExtAuth(t, ctx, name)
	require.Subset(t, needsExt.Id.ExtAuthProviders, []string{realSignerName, signer2Name, signer3Name}, "identity:needs_ext_login ExtAuthProviders should contain all three signers, got %v", needsExt.Id.ExtAuthProviders)
	t.Logf("identity:needs_ext_login reports ExtAuthProviders=%v (count=%d)", needsExt.Id.ExtAuthProviders, len(needsExt.Id.ExtAuthProviders))

	authURL := s.client.GetExternalAuthURL(t, ctx, needsExt.Id.Identifier, realSignerName)

	testutil.DrivePKCEFlow(t, ctx, authURL, pkce.IssuerURL, pkce.Email, pkce.Password)

	added := s.events.WaitFor(t, ctx, "identity", "added", name)
	require.False(t, added.Id.NeedsExtAuth, "identity:added NeedsExtAuth=%t after multi-signer PKCE flow, want false", added.Id.NeedsExtAuth)
	require.True(t, added.Id.Active, "identity:added Active=%t after multi-signer PKCE flow, want true", added.Id.Active)
	t.Logf("identity:added reports NeedsExtAuth=%t Active=%t after multi-signer PKCE flow", added.Id.NeedsExtAuth, added.Id.Active)
}

func (s *extAuthState) urlEnrollForExtAuth(t *testing.T, ctx context.Context, name string) testutil.Event {
	t.Helper()
	controllerBase := overlay.ControllerHostPort()

	identityData := testutil.AddIdentityData{
		IdentityFilename: name,
		ControllerURL:    &controllerBase,
	}
	enrollResp := testutil.Enroll(t, ctx, s.client, identityData)
	require.True(t, enrollResp.Success, "URL AddIdentity should succeed: error=%q\n%s", enrollResp.Error, zet.Logs())

	needsExt := s.events.WaitFor(t, ctx, "identity", "needs_ext_login", name)
	require.NotEmpty(t, needsExt.Id.Identifier, "identity:needs_ext_login Identifier empty")
	require.True(t, needsExt.Id.NeedsExtAuth, "identity:needs_ext_login NeedsExtAuth=%t, want true", needsExt.Id.NeedsExtAuth)
	testutil.AssertValidUrlEnrolledIdentityFile(t, needsExt.Id.Identifier, testutil.EnrollModeNone)
	t.Logf("identity:needs_ext_login Identifier=%s NeedsExtAuth=%t", needsExt.Id.Identifier, needsExt.Id.NeedsExtAuth)

	return needsExt
}
