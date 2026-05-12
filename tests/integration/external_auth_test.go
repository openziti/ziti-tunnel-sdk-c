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
	t.Run("onUrlEnrolledIdentityCompletes", testExternalAuthOnUrlEnrolledIdentityCompletes)
	t.Run("withInvalidProviderFails", testExternalAuthWithInvalidProviderFails)
	t.Run("withoutControllerIdentityFails", testExternalAuthWithoutControllerIdentityFails)
}

func testExternalAuthOnUrlEnrolledIdentityCompletes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	name := identityNameFor(t)
	controllerBase := overlay.ControllerHostPort()
	testUserName := name + "-user"
	testUserPassword := "test-password"

	testUserID, err := overlay.CreateUpdbUser(ctx, testUserName, testUserName, testUserPassword)
	require.NoError(t, err, "create updb test user")

	signerName, policyName := createExtAuthSignerAndPolicy(t, ctx, name, controllerBase+"/oidc", controllerBase+"/oidc")
	require.NoError(t, overlay.CreateIdentityWithExternalId(ctx, name, testUserID, policyName), "create controller identity with externalId=testUserID")

	client, identifier := urlEnrollForExtAuth(t, ctx, name)

	authResp, err := client.GetExternalAuth(ctx, identifier, signerName)
	require.NoError(t, err, "ExternalAuth\n%s", zet.Logs())
	require.NotEmpty(t, authResp.URL, "ExternalAuth should return a non-empty auth URL")

	require.NoError(t, testutil.DriveControllerOIDC(ctx, authResp.URL, controllerBase, testUserName, testUserPassword), "drive controller OIDC flow")

	events, err := testutil.DialEvents(ctx)
	require.NoError(t, err, "dial ZET event pipe")
	t.Cleanup(func() { _ = events.Close() })
	events.WaitFor(t, ctx, "identity", "added", name)

	finalStatus, err := client.GetTunnelStatus(ctx)
	require.NoError(t, err, "Status after ExternalAuth\n%s", zet.Logs())
	finalEntry := finalStatus.FindIdentity(name)
	require.NotNil(t, finalEntry, "identity %q missing from Status after ExternalAuth", name)
	require.False(t, finalEntry.NeedsExtAuth, "NeedsExtAuth should be false after successful ExternalAuth\n%s", zet.Logs())
}

func testExternalAuthWithInvalidProviderFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	name := identityNameFor(t)
	controllerBase := overlay.ControllerHostPort()
	testUserName := name + "-user"
	testUserPassword := "test-password"
	issuer := controllerBase + "/oidc/" + name

	testUserID, err := overlay.CreateUpdbUser(ctx, testUserName, testUserName, testUserPassword)
	require.NoError(t, err, "create updb test user")

	signerName, policyName := createExtAuthSignerAndPolicy(t, ctx, name, issuer, issuer)
	require.NoError(t, overlay.CreateIdentityWithExternalId(ctx, name, testUserID, policyName), "create controller identity with externalId=testUserID")

	client, identifier := urlEnrollForExtAuth(t, ctx, name)

	bogusProvider := signerName + "-bogus"
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
	controllerBase := overlay.ControllerHostPort()
	testUserName := name + "-user"
	testUserPassword := "test-password"
	issuer := controllerBase + "/oidc/" + name

	_, err := overlay.CreateUpdbUser(ctx, testUserName, testUserName, testUserPassword)
	require.NoError(t, err, "create updb test user")

	signerName, _ := createExtAuthSignerAndPolicy(t, ctx, name, issuer, controllerBase+"/oidc")

	client, identifier := urlEnrollForExtAuth(t, ctx, name)

	authResp, err := client.GetExternalAuth(ctx, identifier, signerName)
	require.NoError(t, err, "ExternalAuth\n%s", zet.Logs())
	require.NotEmpty(t, authResp.URL, "ExternalAuth should return a non-empty auth URL")

	require.NoError(t, testutil.DriveControllerOIDC(ctx, authResp.URL, controllerBase, testUserName, testUserPassword), "drive controller OIDC flow")

	events, err := testutil.DialEvents(ctx)
	require.NoError(t, err, "dial ZET event pipe")
	t.Cleanup(func() { _ = events.Close() })
	events.WaitFor(t, ctx, "controller", "disconnected", name)

	finalStatus, err := client.GetTunnelStatus(ctx)
	require.NoError(t, err, "Status after failed external auth\n%s", zet.Logs())
	finalEntry := finalStatus.FindIdentity(name)
	require.NotNil(t, finalEntry, "identity %q should still exist in Status", name)
	require.True(t, finalEntry.NeedsExtAuth, "NeedsExtAuth should remain true after controller rejection")
	t.Logf("External auth correctly failed without controller identity; NeedsExtAuth=%t", finalEntry.NeedsExtAuth)
}

func createExtAuthSignerAndPolicy(t *testing.T, ctx context.Context, name, issuer, externalAuthURL string) (string, string) {
	t.Helper()
	signerName := name + "-signer"
	policyName := name + "-policy"

	jwksURI, err := testutil.DiscoverOIDCJWKS(ctx, overlay.ControllerHostPort()+"/oidc")
	require.NoError(t, err, "discover controller OIDC jwks_uri")

	signerID, err := overlay.CreateExtJwtSigner(ctx, signerName, issuer, jwksURI, "openziti", "openziti", externalAuthURL)
	require.NoError(t, err, "create ext-jwt-signer")
	require.NoError(t, overlay.CreateAuthPolicyForExtJwt(ctx, policyName, signerID), "create auth policy with ext-jwt-signer")

	return signerName, policyName
}

func urlEnrollForExtAuth(t *testing.T, ctx context.Context, name string) (*testutil.IPCClient, string) {
	t.Helper()
	controllerBase := overlay.ControllerHostPort()

	events, err := testutil.DialEvents(ctx)
	require.NoError(t, err, "dial ZET event pipe")
	defer func() { _ = events.Close() }()

	client, err := testutil.DialIPC(ctx)
	require.NoError(t, err, "dial ZET IPC pipe")
	t.Cleanup(func() { _ = client.Close() })

	identityData := testutil.AddIdentityData{
		IdentityFilename: name,
		ControllerURL:    &controllerBase,
	}
	enrollResp, err := client.AddIdentity(ctx, identityData)
	require.NoError(t, err, "URL AddIdentity send\n%s", zet.Logs())
	require.True(t, enrollResp.Success, "URL AddIdentity should succeed: error=%q\n%s", enrollResp.Error, zet.Logs())

	events.WaitFor(t, ctx, "identity", "needs_ext_login", name)

	status, err := client.GetTunnelStatus(ctx)
	require.NoError(t, err, "Status after URL AddIdentity\n%s", zet.Logs())
	entry := status.FindIdentity(name)
	require.NotNil(t, entry, "identity %q not found in Status after URL AddIdentity", name)

	return client, entry.Identifier
}
