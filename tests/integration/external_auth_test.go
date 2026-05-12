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
}

func testExternalAuthOnUrlEnrolledIdentityCompletes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	name := identityNameFor(t)
	controllerBase := overlay.ControllerHostPort()
	enrolled := newEnrolledExtAuth(t, ctx, name, controllerBase+"/oidc")

	authResp, err := enrolled.Client.GetExternalAuth(ctx, enrolled.Identifier, enrolled.SignerName)
	require.NoError(t, err, "ExternalAuth\n%s", zet.Logs())
	require.NotEmpty(t, authResp.URL, "ExternalAuth should return a non-empty auth URL")

	require.NoError(t, testutil.DriveControllerOIDC(ctx, authResp.URL, controllerBase, enrolled.TestUserName, enrolled.TestUserPass), "drive controller OIDC flow")

	events, err := testutil.DialEvents(ctx)
	require.NoError(t, err, "dial ZET event pipe")
	t.Cleanup(func() { _ = events.Close() })
	events.WaitFor(t, ctx, "identity", "added", name)

	finalStatus, err := enrolled.Client.GetTunnelStatus(ctx)
	require.NoError(t, err, "Status after ExternalAuth\n%s", zet.Logs())
	finalEntry := finalStatus.FindIdentity(name)
	require.NotNil(t, finalEntry, "identity %q missing from Status after ExternalAuth", name)
	require.False(t, finalEntry.NeedsExtAuth, "NeedsExtAuth should be false after successful ExternalAuth\n%s", zet.Logs())
}

func testExternalAuthWithInvalidProviderFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	name := identityNameFor(t)
	issuer := overlay.ControllerHostPort() + "/oidc/" + name
	enrolled := newEnrolledExtAuth(t, ctx, name, issuer)

	bogusProvider := enrolled.SignerName + "-bogus"
	resp, err := enrolled.Client.ExternalAuth(ctx, enrolled.Identifier, bogusProvider)
	require.NoError(t, err, "ExternalAuth send\n%s", zet.Logs())
	require.False(t, resp.Success, "ExternalAuth should fail for unknown provider %q\n%s", bogusProvider, zet.Logs())
	require.NotEmpty(t, resp.Error, "expected non-empty error from ExternalAuth failure")
	t.Logf("ExternalAuth correctly failed for invalid provider: code=%d error=%q", resp.Code, resp.Error)
}

type enrolledExtAuth struct {
	Client       *testutil.IPCClient
	Identifier   string
	SignerName   string
	TestUserName string
	TestUserPass string
}

func newEnrolledExtAuth(t *testing.T, ctx context.Context, name, issuer string) *enrolledExtAuth {
	t.Helper()

	controllerBase := overlay.ControllerHostPort()
	signerName := name + "-signer"
	policyName := name + "-policy"
	testUserName := name + "-user"
	testUserPassword := "test-password"

	testUserID, err := overlay.CreateUpdbUser(ctx, testUserName, testUserName, testUserPassword)
	require.NoError(t, err, "create updb test user")

	jwksURI, err := testutil.DiscoverOIDCJWKS(ctx, controllerBase+"/oidc")
	require.NoError(t, err, "discover controller OIDC jwks_uri")

	signerID, err := overlay.CreateExtJwtSigner(ctx, signerName, issuer, jwksURI, "openziti", "openziti", issuer)
	require.NoError(t, err, "create ext-jwt-signer")
	require.NoError(t, overlay.CreateAuthPolicyForExtJwt(ctx, policyName, signerID), "create auth policy with ext-jwt-signer")
	require.NoError(t, overlay.CreateIdentityWithExternalId(ctx, name, testUserID, policyName), "create controller identity with externalId=testUserID")

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

	return &enrolledExtAuth{
		Client:       client,
		Identifier:   entry.Identifier,
		SignerName:   signerName,
		TestUserName: testUserName,
		TestUserPass: testUserPassword,
	}
}
