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
	"encoding/json"
	"testing"
	"time"

	"github.com/openziti/ziti-tunnel-sdk-c/tests/integration/testutil"
	"github.com/stretchr/testify/require"
)

func TestListIdentities(t *testing.T) {
	t.Run("containsAddedIdentity", testListIdentitiesContainsAddedIdentity)
}

func testListIdentitiesContainsAddedIdentity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	name := identityNameFor(t)
	jwt, err := overlay.CreateIdentityJWT(ctx, name)
	require.NoError(t, err, "mint JWT via overlay")
	require.NotEmpty(t, jwt)

	client, err := testutil.DialIPC(ctx)
	require.NoError(t, err, "dial ZET IPC pipe")
	t.Cleanup(func() { _ = client.Close() })

	addResp, err := client.AddIdentity(ctx, testutil.AddIdentityData{
		IdentityFilename: name,
		JwtContent:       jwt,
	})
	require.NoError(t, err, "AddIdentity send\n%s", zet.Logs())
	require.True(t, addResp.Success, "AddIdentity failed: error=%q code=%d", addResp.Error, addResp.Code)

	listResp, err := client.ListIdentities(ctx)
	require.NoError(t, err, "ListIdentities send\n%s", zet.Logs())
	require.True(t, listResp.Success, "ListIdentities failed: error=%q code=%d", listResp.Error, listResp.Code)

	var data testutil.IdentityListData
	require.NoError(t, json.Unmarshal(listResp.Data, &data), "unmarshal ListIdentities data: %s", listResp.Data)

	identifier := zet.IdentityIdentifier(name)
	var found *testutil.IdentityInfo
	for i := range data.Identities {
		if data.Identities[i].Config == identifier {
			found = &data.Identities[i]
			break
		}
	}
	require.NotNil(t, found, "ListIdentities did not contain %q in %d entries", identifier, len(data.Identities))
	require.Equal(t, name, found.Name, "identity Name should match the JWT subject name")
	require.NotEmpty(t, found.Id, "identity Id should be set")
	require.NotEmpty(t, found.Network, "identity Network should be set")
	t.Logf("ListIdentities reported identity %q (id=%s, network=%s)", found.Name, found.Id, found.Network)
}
