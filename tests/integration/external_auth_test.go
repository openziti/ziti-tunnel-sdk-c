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

func TestExternalAuth(t *testing.T) {
	overlay.RequireCATrusted(t)
	if dex == nil {
		t.Skip("dex is not configured (-dex-bin not provided)")
	}
	t.Run("onUrlEnrolledIdentityCompletes", testExternalAuthOnUrlEnrolledIdentityCompletes)
	t.Run("withInvalidProviderFails", testExternalAuthWithInvalidProviderFails)
	t.Run("withoutControllerIdentityFails", testExternalAuthWithoutControllerIdentityFails)
	t.Run("withMultipleSignersCompletes", testExternalAuthWithMultipleSignersCompletes)
}

func testExternalAuthOnUrlEnrolledIdentityCompletes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	name := identityNameFor(t)

	signerName, policyName := createDexSignerAndPolicy(t, ctx, name, dex.ClientIDs[0])
	t.Logf("creating controller identity %q with externalId=%q bound to policy %q", name, dex.ExternalID, policyName)
	require.NoError(t, overlay.CreateIdentityWithExternalId(ctx, name, dex.ExternalID, policyName), "create controller identity with externalId=dex user email")
	t.Logf("controller identity %q created", name)

	cleanupCtx := context.Background()
	t.Cleanup(func() {
		_ = overlay.DeleteIdentity(cleanupCtx, name)
		_ = overlay.DeleteAuthPolicy(cleanupCtx, policyName)
		_ = overlay.DeleteExtJwtSigner(cleanupCtx, signerName)
	})

	client, events, identifier := urlEnrollForExtAuth(t, ctx, name)

	t.Logf("requesting external auth URL from ZET for signer=%q", signerName)
	authResp, err := client.GetExternalAuth(ctx, identifier, signerName)
	require.NoError(t, err, "ExternalAuth\n%s", zet.Logs())
	require.NotEmpty(t, authResp.URL, "ExternalAuth should return a non-empty auth URL")
	t.Logf("ExternalAuth returned auth URL: %s", authResp.URL)

	t.Logf("driving dex OIDC flow (issuer=%s email=%s)", dex.IssuerURL, dex.Email)
	require.NoError(t, testutil.DriveDexOIDC(ctx, authResp.URL, dex.IssuerURL, dex.Email, dex.Password), "drive dex OIDC flow")
	t.Logf("dex OIDC flow completed")

	t.Logf("waiting for identity:added event for %q", name)
	events.WaitFor(t, ctx, "identity", "added", name)
	t.Logf("identity:added event received")

	t.Logf("fetching tunnel status to confirm NeedsExtAuth cleared")
	finalStatus, err := client.GetTunnelStatus(ctx)
	require.NoError(t, err, "Status after ExternalAuth\n%s", zet.Logs())
	finalEntry := finalStatus.FindIdentity(name)
	require.NotNil(t, finalEntry, "identity %q missing from Status after ExternalAuth", name)
	require.False(t, finalEntry.NeedsExtAuth, "NeedsExtAuth should be false after successful ExternalAuth\n%s", zet.Logs())
	t.Logf("status reports NeedsExtAuth=%t after successful ExternalAuth", finalEntry.NeedsExtAuth)
}

func testExternalAuthWithInvalidProviderFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	name := identityNameFor(t)

	signerName, policyName := createDexSignerAndPolicy(t, ctx, name, dex.ClientIDs[0])
	t.Logf("creating controller identity %q with externalId=%q bound to policy %q", name, dex.ExternalID, policyName)
	require.NoError(t, overlay.CreateIdentityWithExternalId(ctx, name, dex.ExternalID, policyName), "create controller identity with externalId=dex user email")
	t.Logf("controller identity %q created", name)

	cleanupCtx := context.Background()
	t.Cleanup(func() {
		_ = overlay.DeleteIdentity(cleanupCtx, name)
		_ = overlay.DeleteAuthPolicy(cleanupCtx, policyName)
		_ = overlay.DeleteExtJwtSigner(cleanupCtx, signerName)
	})

	client, _, identifier := urlEnrollForExtAuth(t, ctx, name)

	bogusProvider := signerName + "-bogus"
	t.Logf("sending ExternalAuth with bogus provider %q (should be rejected)", bogusProvider)
	resp, err := client.ExternalAuth(ctx, identifier, bogusProvider)
	require.NoError(t, err, "ExternalAuth send\n%s", zet.Logs())
	require.False(t, resp.Success, "ExternalAuth should fail for unknown provider %q\n%s", bogusProvider, zet.Logs())
	require.NotEmpty(t, resp.Error, "expected non-empty error from ExternalAuth failure")
	t.Logf("ExternalAuth correctly failed for invalid provider: code=%d error=%q", resp.Code, resp.Error)
}

func testExternalAuthWithoutControllerIdentityFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	name := identityNameFor(t)

	signerName, _ := createDexSignerAndPolicy(t, ctx, name, dex.ClientIDs[0])
	// Deliberately DO NOT create a controller identity with externalId. The
	// OIDC flow at dex still succeeds, but the controller rejects login since
	// nothing maps test@example.com to a known identity.
	t.Logf("skipping controller identity creation on purpose (controller should reject because externalId=%q is unmapped)", dex.ExternalID)

	cleanupCtx := context.Background()
	t.Cleanup(func() {
		_ = overlay.DeleteAuthPolicy(cleanupCtx, name+"-policy")
		_ = overlay.DeleteExtJwtSigner(cleanupCtx, signerName)
	})

	client, events, identifier := urlEnrollForExtAuth(t, ctx, name)

	t.Logf("requesting external auth URL from ZET for signer=%q", signerName)
	authResp, err := client.GetExternalAuth(ctx, identifier, signerName)
	require.NoError(t, err, "ExternalAuth\n%s", zet.Logs())
	require.NotEmpty(t, authResp.URL, "ExternalAuth should return a non-empty auth URL")
	t.Logf("ExternalAuth returned auth URL: %s", authResp.URL)

	t.Logf("driving dex OIDC flow (issuer=%s email=%s)", dex.IssuerURL, dex.Email)
	require.NoError(t, testutil.DriveDexOIDC(ctx, authResp.URL, dex.IssuerURL, dex.Email, dex.Password), "drive dex OIDC flow")
	t.Logf("dex OIDC flow completed; controller should reject because no identity has externalId=%q", dex.ExternalID)

	t.Logf("waiting for controller:disconnected event for %q", name)
	events.WaitFor(t, ctx, "controller", "disconnected", name)
	t.Logf("controller:disconnected event received")

	t.Logf("fetching tunnel status to confirm NeedsExtAuth stayed true")
	finalStatus, err := client.GetTunnelStatus(ctx)
	require.NoError(t, err, "Status after failed external auth\n%s", zet.Logs())
	finalEntry := finalStatus.FindIdentity(name)
	require.NotNil(t, finalEntry, "identity %q should still exist in Status", name)
	require.True(t, finalEntry.NeedsExtAuth, "NeedsExtAuth should remain true after controller rejection")
	t.Logf("status reports NeedsExtAuth=%t after controller rejection", finalEntry.NeedsExtAuth)
}

func testExternalAuthWithMultipleSignersCompletes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	name := identityNameFor(t)
	jwksURI := dex.JWKSURI()

	realSignerName := name + "-signer-real"
	signer2Name := name + "-signer-2"
	signer3Name := name + "-signer-3"
	// Only the real signer is exercised by the auth flow. signer-2 and signer-3
	// just need to exist as distinct providers in the policy; the controller
	// rejects duplicate issuers via a unique index, so they each get a unique
	// sub-path under dex (no traffic ever hits those endpoints).
	t.Logf("creating real-issuer ext-jwt-signer %q", realSignerName)
	realSignerID, err := overlay.CreateExtJwtSigner(ctx, testutil.ExtJwtSignerSpec{
		Name:     realSignerName,
		Issuer:   dex.IssuerURL,
		JWKS:     jwksURI,
		ClientID: dex.ClientIDs[0],
		Claim:    "email",
		Scopes:   []string{"email"},
	})
	require.NoError(t, err, "create real-issuer ext-jwt-signer")
	t.Logf("real-issuer signer created with id=%s", realSignerID)

	t.Logf("creating placeholder ext-jwt-signer %q (distinct sub-path under dex)", signer2Name)
	signer2ID, err := overlay.CreateExtJwtSigner(ctx, testutil.ExtJwtSignerSpec{
		Name:     signer2Name,
		Issuer:   dex.IssuerURL + "/" + signer2Name,
		JWKS:     jwksURI,
		ClientID: dex.ClientIDs[1],
		Claim:    "email",
	})
	require.NoError(t, err, "create ext-jwt-signer 2")
	t.Logf("placeholder signer 2 created with id=%s", signer2ID)

	t.Logf("creating placeholder ext-jwt-signer %q (distinct sub-path under dex)", signer3Name)
	signer3ID, err := overlay.CreateExtJwtSigner(ctx, testutil.ExtJwtSignerSpec{
		Name:     signer3Name,
		Issuer:   dex.IssuerURL + "/" + signer3Name,
		JWKS:     jwksURI,
		ClientID: dex.ClientIDs[2],
		Claim:    "email",
	})
	require.NoError(t, err, "create ext-jwt-signer 3")
	t.Logf("placeholder signer 3 created with id=%s", signer3ID)

	policyName := name + "-policy"
	t.Logf("creating multi-signer auth policy %q binding all three signers", policyName)
	require.NoError(t, overlay.CreateAuthPolicyForExtJwt(ctx, policyName, realSignerID, signer2ID, signer3ID), "create multi-signer auth policy")
	t.Logf("auth policy %q created", policyName)

	t.Logf("creating controller identity %q with externalId=%q bound to policy %q", name, dex.ExternalID, policyName)
	require.NoError(t, overlay.CreateIdentityWithExternalId(ctx, name, dex.ExternalID, policyName), "create controller identity with externalId=dex user email")
	t.Logf("controller identity %q created", name)

	cleanupCtx := context.Background()
	t.Cleanup(func() {
		_ = overlay.DeleteIdentity(cleanupCtx, name)
		_ = overlay.DeleteAuthPolicy(cleanupCtx, policyName)
		_ = overlay.DeleteExtJwtSigner(cleanupCtx, realSignerName)
		_ = overlay.DeleteExtJwtSigner(cleanupCtx, signer2Name)
		_ = overlay.DeleteExtJwtSigner(cleanupCtx, signer3Name)
	})

	client, events, identifier := urlEnrollForExtAuth(t, ctx, name)

	t.Logf("fetching tunnel status to confirm all three providers listed")
	status, err := client.GetTunnelStatus(ctx)
	require.NoError(t, err, "Status after URL AddIdentity\n%s", zet.Logs())
	entry := status.FindIdentity(name)
	require.NotNil(t, entry, "identity %q not found in Status", name)
	require.Subset(t, entry.ExtAuthProviders, []string{realSignerName, signer2Name, signer3Name}, "ExtAuthProviders should contain all three signers, got %v", entry.ExtAuthProviders)
	t.Logf("status reports ExtAuthProviders=%v (count=%d)", entry.ExtAuthProviders, len(entry.ExtAuthProviders))

	t.Logf("requesting external auth URL from ZET for real signer=%q", realSignerName)
	authResp, err := client.GetExternalAuth(ctx, identifier, realSignerName)
	require.NoError(t, err, "ExternalAuth\n%s", zet.Logs())
	require.NotEmpty(t, authResp.URL, "ExternalAuth should return a non-empty auth URL")
	t.Logf("ExternalAuth returned auth URL: %s", authResp.URL)

	t.Logf("driving dex OIDC flow (issuer=%s email=%s)", dex.IssuerURL, dex.Email)
	require.NoError(t, testutil.DriveDexOIDC(ctx, authResp.URL, dex.IssuerURL, dex.Email, dex.Password), "drive dex OIDC flow")
	t.Logf("dex OIDC flow completed")

	t.Logf("waiting for identity:added event for %q", name)
	events.WaitFor(t, ctx, "identity", "added", name)
	t.Logf("identity:added event received")

	t.Logf("fetching tunnel status to confirm NeedsExtAuth cleared")
	finalStatus, err := client.GetTunnelStatus(ctx)
	require.NoError(t, err, "Status after ExternalAuth\n%s", zet.Logs())
	finalEntry := finalStatus.FindIdentity(name)
	require.NotNil(t, finalEntry, "identity %q missing from Status after ExternalAuth", name)
	require.False(t, finalEntry.NeedsExtAuth, "NeedsExtAuth should be false after successful ExternalAuth\n%s", zet.Logs())
	t.Logf("status reports NeedsExtAuth=%t after multi-signer ExternalAuth", finalEntry.NeedsExtAuth)
}

// createDexSignerAndPolicy registers an ext-jwt-signer pointed at dex with the
// given audience/client_id, plus a single-signer auth policy. Returns
// (signerName, policyName). The signer maps dex's email claim to externalId.
func createDexSignerAndPolicy(t *testing.T, ctx context.Context, name, clientID string) (string, string) {
	t.Helper()
	signerName := name + "-signer"
	policyName := name + "-policy"

	jwksURI := dex.JWKSURI()

	t.Logf("creating ext-jwt-signer %q pointing at dex (issuer=%s clientID=%s)", signerName, dex.IssuerURL, clientID)
	signerID, err := overlay.CreateExtJwtSigner(ctx, testutil.ExtJwtSignerSpec{
		Name:     signerName,
		Issuer:   dex.IssuerURL,
		JWKS:     jwksURI,
		ClientID: clientID,
		Claim:    "email",
		Scopes:   []string{"email"},
	})
	require.NoError(t, err, "create ext-jwt-signer")
	t.Logf("ext-jwt-signer %q created with id=%s", signerName, signerID)

	t.Logf("creating auth policy %q with ext-jwt-signer %s", policyName, signerID)
	require.NoError(t, overlay.CreateAuthPolicyForExtJwt(ctx, policyName, signerID), "create auth policy with ext-jwt-signer")
	t.Logf("auth policy %q created", policyName)

	return signerName, policyName
}

func urlEnrollForExtAuth(t *testing.T, ctx context.Context, name string) (*testutil.IPCClient, *testutil.EventClient, string) {
	t.Helper()
	controllerBase := overlay.ControllerHostPort()

	events, err := zet.DialEvents(ctx)
	require.NoError(t, err, "dial ZET event pipe")
	t.Cleanup(func() { _ = events.Close() })

	client, err := zet.DialIPC(ctx)
	require.NoError(t, err, "dial ZET IPC pipe")
	t.Cleanup(func() { _ = client.Close() })

	identityData := testutil.AddIdentityData{
		IdentityFilename: name,
		ControllerURL:    &controllerBase,
	}
	t.Logf("sending URL AddIdentity for %q with ControllerURL=%s", name, controllerBase)
	enrollResp, err := client.AddIdentity(ctx, identityData)
	require.NoError(t, err, "URL AddIdentity send\n%s", zet.Logs())
	require.True(t, enrollResp.Success, "URL AddIdentity should succeed: error=%q\n%s", enrollResp.Error, zet.Logs())
	t.Logf("URL AddIdentity succeeded for %q", name)

	t.Logf("waiting for identity:needs_ext_login event for %q", name)
	events.WaitFor(t, ctx, "identity", "needs_ext_login", name)
	t.Logf("identity:needs_ext_login event received")

	t.Logf("fetching tunnel status to get Identifier")
	status, err := client.GetTunnelStatus(ctx)
	require.NoError(t, err, "Status after URL AddIdentity\n%s", zet.Logs())
	entry := status.FindIdentity(name)
	require.NotNil(t, entry, "identity %q not found in Status after URL AddIdentity", name)
	t.Logf("found %q in status with Identifier=%s NeedsExtAuth=%t", name, entry.Identifier, entry.NeedsExtAuth)

	return client, events, entry.Identifier
}
