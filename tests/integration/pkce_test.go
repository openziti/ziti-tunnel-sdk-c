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

func TestPKCEUp(t *testing.T) {
	if pkce == nil {
		t.Skip("PKCE IdP is not configured (-pkce-bin not provided)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	t.Logf("running OIDC discovery against PKCE issuer=%s", pkce.IssuerURL)
	jwks, err := testutil.DiscoverOIDCJWKS(ctx, pkce.IssuerURL)
	require.NoError(t, err, "OIDC discovery against PKCE IdP")
	require.Equal(t, pkce.JWKSURI(), jwks, "jwks_uri from discovery should match advertised issuer/keys")
	t.Logf("OIDC discovery returned jwks_uri=%s (matches advertised %s)", jwks, pkce.JWKSURI())
}
