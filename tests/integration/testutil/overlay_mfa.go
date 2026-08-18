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

package testutil

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// IdentityID returns the controller's id for the identity with this name.
func (o *Overlay) IdentityID(t *testing.T, name string) string {
	out, err := o.execZiti("edge list identities %s -j", fmt.Sprintf("name=%q", name))
	require.NoError(t, err, "list identities name=%s", name)

	var resp struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(out, &resp), "parse identities list for %s", name)
	require.Len(t, resp.Data, 1, "expected exactly one identity named %s", name)
	return resp.Data[0].ID
}

// SetIdentityAuthPolicy moves an existing identity onto another auth policy, the way an
// administrator tightening or relaxing a requirement would.
func (o *Overlay) SetIdentityAuthPolicy(t *testing.T, name, authPolicy string) {
	t.Logf("moving identity %q onto auth policy %q", name, authPolicy)
	_, err := o.execZiti("edge update identity %s -P %s", name, authPolicy)
	require.NoError(t, err, "update identity %s to auth policy %s", name, authPolicy)

	// On a cluster the client can re-authenticate against any controller, so the write has to
	// have propagated first.
	// TODO: use WaitForDataModelConsensus once the data-model index reflects these writes.
	if o.ZitiClusterSize > 1 {
		time.Sleep(500 * time.Millisecond)
	}
}

// RemoveIdentityMFA removes an identity's TOTP enrollment as an administrator would.
// There is no `ziti edge delete mfa`, so this goes at the management API.
func (o *Overlay) RemoveIdentityMFA(t *testing.T, name string) {
	id := o.IdentityID(t, name)
	token := o.managementToken(t)

	req, err := http.NewRequest(http.MethodDelete,
		fmt.Sprintf("%s/edge/management/v1/identities/%s/mfa", o.ControllerHostPort(), id), nil)
	require.NoError(t, err, "build delete mfa request")
	req.Header.Set("zt-session", token)

	resp, err := insecureClient(10 * time.Second).Do(req)
	require.NoError(t, err, "delete mfa for %s", name)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "delete mfa for %s returned %d", name, resp.StatusCode)
}

// IdentityMfaEnabled reports whether the controller considers this identity enrolled.
func (o *Overlay) IdentityMfaEnabled(t *testing.T, name string) bool {
	out, err := o.execZiti("edge list identities %s -j", fmt.Sprintf("name=%q", name))
	require.NoError(t, err, "list identities name=%s", name)

	var resp struct {
		Data []struct {
			IsMfaEnabled bool `json:"isMfaEnabled"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(out, &resp), "parse identities list for %s", name)
	require.Len(t, resp.Data, 1, "expected exactly one identity named %s", name)
	return resp.Data[0].IsMfaEnabled
}

// managementToken logs in to the management API and returns a session token.
func (o *Overlay) managementToken(t *testing.T) string {
	body, err := json.Marshal(map[string]string{"username": o.ControllerUser, "password": o.ControllerPassword})
	require.NoError(t, err, "encode admin credentials")

	resp, err := insecureClient(10*time.Second).Post(
		o.ControllerHostPort()+"/edge/management/v1/authenticate?method=password",
		"application/json", bytes.NewReader(body))
	require.NoError(t, err, "admin authenticate")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "admin authenticate returned %d", resp.StatusCode)

	var authResp struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&authResp), "decode admin authenticate")
	require.NotEmpty(t, authResp.Data.Token, "admin authenticate returned no token")
	return authResp.Data.Token
}

// insecureClient skips TLS verification so calls work whether or not the overlay's CA is
// in the OS trust store.
func insecureClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
}
