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

// TestDexUp is a smoke test for the dex IdP wiring. It only verifies that the
// process is up and that OIDC discovery returns the JWKS URI dex advertises.
// Drives no auth flow yet -- once this passes, build on it to point an ext-jwt
// signer at dex.IssuerURL.
func TestDexUp(t *testing.T) {
	if dex == nil {
		t.Skip("dex is not configured (-dex-bin not provided)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	jwks, err := testutil.DiscoverOIDCJWKS(ctx, dex.IssuerURL)
	require.NoError(t, err, "OIDC discovery against dex")
	require.Equal(t, dex.JWKSURI(), jwks, "jwks_uri from discovery should match advertised issuer/keys")
	t.Logf("dex issuer=%s jwks=%s", dex.IssuerURL, jwks)
}
