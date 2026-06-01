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
	"testing"

	"github.com/stretchr/testify/require"
)

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
