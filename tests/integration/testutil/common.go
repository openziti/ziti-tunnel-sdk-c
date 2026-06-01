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

// Shared, cross-cutting test helpers that span more than one component (overlay,
// zet, ipc, identity file). Helpers specific to a single component live with it.

package testutil

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const workingExtJwtSignerName = "TestExternalAuth-signer-working"

// CreateJwt creates an enrollment JWT for name on the overlay and asserts it is
// non-empty.
func CreateJwt(t *testing.T, overlay *Overlay, name string) string {
	t.Logf("creating JWT for %q", name)
	jwt, err := overlay.CreateIdentityJWT(name)
	require.NoError(t, err, "failed to create JWT for %q", name)
	require.NotEmpty(t, jwt, "JWT content should not be empty")
	return jwt
}

// EnrollJwtIdentity creates a JWT for name on the overlay, adds it to zet, waits
// for the identity:added event, asserts the on-disk identity file, and returns
// the added event.
func EnrollJwtIdentity(t *testing.T, overlay *Overlay, zet *ZET, name string) IdentityEvent {
	jwt := CreateJwt(t, overlay, name)
	identityData := AddIdentityData{
		IdentityFilename: name,
		JwtContent:       &jwt,
	}
	resp := AddIdentity(t, zet.Commands, identityData)
	require.True(t, resp.Success(), "AddIdentity failed: error=%q code=%d\n%s", resp.Error, resp.Code, zet.LogPath())

	added := zet.Events.WaitForIdentityEvent(t, "added", name)
	require.NotEmpty(t, added.Id.Identifier, "identity:added Identifier empty")
	AssertValidJwtEnrolledIdentityFile(t, added.Id.Identifier)
	return added
}

// EnrollUrlIdentityToNone adds name to zet by controller URL (enroll-to-none),
// waits for the needs_ext_login event, asserts NeedsExtAuth and the on-disk
// file, and returns the event.
func EnrollUrlIdentityToNone(t *testing.T, overlay *Overlay, zet *ZET, name string) IdentityEvent {
	controllerURL := overlay.ControllerHostPort()
	identityData := AddIdentityData{
		IdentityFilename: name,
		ControllerURL:    &controllerURL,
	}
	resp := AddIdentity(t, zet.Commands, identityData)
	require.True(t, resp.Success(), "URL AddIdentity should succeed: error=%q code=%d\n%s", resp.Error, resp.Code, zet.LogPath())

	event := zet.Events.WaitForIdentityEvent(t, "needs_ext_login", name)
	require.NotEmpty(t, event.Id.Identifier, "identity:needs_ext_login Identifier empty")
	require.True(t, event.Id.NeedsExtAuth, "identity:needs_ext_login NeedsExtAuth=%t", event.Id.NeedsExtAuth)
	AssertValidUrlEnrolledIdentityFile(t, event.Id.Identifier, EnrollModeNone)
	return event
}

// SetupWorkingExtJwtSigner adopts idp.SignerName when set (failing if it does
// not exist on the controller), otherwise creates or reuses a harness signer.
// Returns the signer name and id.
func SetupWorkingExtJwtSigner(t *testing.T, overlay *Overlay, idp *IdP) (string, string) {
	if idp.SignerName != "" {
		id, found := overlay.FindExtJwtSignerId(t, idp.SignerName)
		if !found {
			t.Fatalf("idp.signerName=%q is set but no ext-jwt-signer with that name exists on the controller; fix the name or create the signer", idp.SignerName)
		}
		return idp.SignerName, id
	}

	if !idp.UseTestHarnessIdP {
		t.Fatal("idp.signerName is empty: the working ext-jwt-signer is only auto-created when the harness runs its own IdP (useTestHarnessIdP=true); set idp.signerName to use your own")
	}

	if id, found := overlay.FindExtJwtSignerId(t, workingExtJwtSignerName); found {
		return workingExtJwtSignerName, id
	}
	id := overlay.CreateExtJwtSigner(t, ExtJwtSignerSpec{
		Name:     workingExtJwtSignerName,
		Issuer:   idp.IssuerURL,
		JWKS:     idp.JWKSURI(),
		ClientID: idp.ClientIDWorks,
		Audience: idp.Audience,
		Claim:    "email",
		Scopes:   strings.Fields(idp.Scopes),
	})
	return workingExtJwtSignerName, id
}
