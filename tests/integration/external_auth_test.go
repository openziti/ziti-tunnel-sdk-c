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
}

func testExternalAuthOnUrlEnrolledIdentityCompletes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	controllerBase := overlay.ControllerHostPort()
	signerName := identityNameFor(t) + "-signer"
	policyName := identityNameFor(t) + "-policy"
	identityName := identityNameFor(t)

	adminID, err := overlay.IdentityID(ctx, "Default Admin")
	require.NoError(t, err, "look up admin identity ID")

	jwksURI, err := testutil.DiscoverOIDCJWKS(ctx, controllerBase+"/oidc")
	require.NoError(t, err, "discover controller OIDC jwks_uri")

	signerID, err := overlay.CreateExtJwtSigner(ctx,
		signerName,
		controllerBase+"/oidc",
		jwksURI,
		"openziti",
		"openziti",
		controllerBase+"/oidc",
	)
	require.NoError(t, err, "create ext-jwt-signer")
	require.NoError(t, overlay.CreateAuthPolicyForExtJwt(ctx, policyName, signerID), "create auth policy with ext-jwt-signer")
	require.NoError(t, overlay.CreateIdentityWithExternalId(ctx, identityName, adminID, policyName), "create controller identity with externalId=adminID")

	events, err := testutil.DialEvents(ctx)
	require.NoError(t, err, "dial ZET event pipe")
	t.Cleanup(func() { _ = events.Close() })

	client, err := testutil.DialIPC(ctx)
	require.NoError(t, err, "dial ZET IPC pipe")
	t.Cleanup(func() { _ = client.Close() })

	identityData := testutil.AddIdentityData{
		IdentityFilename: identityName,
		ControllerURL:    &controllerBase,
	}
	enrollResp, err := client.AddIdentity(ctx, identityData)
	require.NoError(t, err, "URL AddIdentity send\n%s", zet.Logs())
	require.True(t, enrollResp.Success, "URL AddIdentity should succeed: error=%q\n%s", enrollResp.Error, zet.Logs())

	events.WaitFor(t, ctx, "identity", "needs_ext_login", identityName)

	status, err := client.GetTunnelStatus(ctx)
	require.NoError(t, err, "Status after URL AddIdentity\n%s", zet.Logs())
	entry := status.FindIdentity(identityName)
	require.NotNil(t, entry, "identity %q not found in Status after URL AddIdentity", identityName)

	authResp, err := client.GetExternalAuth(ctx, entry.Identifier, signerName)
	require.NoError(t, err, "ExternalAuth\n%s", zet.Logs())
	require.NotEmpty(t, authResp.URL, "ExternalAuth should return a non-empty auth URL")

	require.NoError(t, testutil.DriveControllerOIDC(ctx, authResp.URL, controllerBase, "admin", "admin"), "drive controller OIDC flow")

	events.WaitFor(t, ctx, "identity", "added", identityName)

	finalStatus, err := client.GetTunnelStatus(ctx)
	require.NoError(t, err, "Status after ExternalAuth\n%s", zet.Logs())
	finalEntry := finalStatus.FindIdentity(identityName)
	require.NotNil(t, finalEntry, "identity %q missing from Status after ExternalAuth", identityName)
	require.False(t, finalEntry.NeedsExtAuth, "NeedsExtAuth should be false after successful ExternalAuth\n%s", zet.Logs())
}
