//go:build windows || darwin

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
	"testing"

	"github.com/openziti/ziti-tunnel-sdk-c/tests/integration/testutil"
	"github.com/stretchr/testify/require"
)

func TestKeychainEnroll(t *testing.T) {
	t.Run("succeeds", keychainEnrollSucceeds)
}

func keychainEnrollSucceeds(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		idName := "test_keychain_enroll"
		jwt := state.overlay.GetJwtFromController(t, idName)

		identityData := testutil.AddIdentityData{
			IdentityFilename: idName,
			JwtContent:       &jwt,
			UseKeychain:      true,
		}
		addResp := state.zetClient.AddIdentity(t, identityData)
		addResp.AssertSuccess()

		added := state.zetClient.WaitForIdentityEvent(t, "added", idName)
		keyRef := testutil.AssertKeychainKeyRef(t, added.Id.Identifier)
		t.Cleanup(func() { testutil.RemoveKeychainKey(t, keyRef) })

		require.True(t, added.Id.Active, "identity:added Active=%t", added.Id.Active)
		state.zetClient.WaitForControllerEvent(t, "connected", idName)

		require.True(t, testutil.KeychainKeyExists(t, keyRef), "private key %q should be in the OS keychain after enroll", keyRef)
	})
}
