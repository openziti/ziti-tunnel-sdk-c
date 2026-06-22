//go:build windows

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

func TestKeychain(t *testing.T) {
	// Happy path "enrollment succeeds" is covered as a pre-req in this suite
	t.Run("forgetIdentityRemovesKey", forgetIdentityRemovesKey)
	t.Run("reEnrollSucceedsAfterReset", reEnrollSucceedsAfterReset)
}

// enrollWithKeychain enrolls idName with UseKeychain, asserts the key reference in the
// identity file, asserts the key is in the OS keychain, registers its cleanup, and
// returns the added event and ref.
func enrollWithKeychain(t *testing.T, idName string) (testutil.IdentityEvent, string) {
	jwt := state.overlay.GetJwtFromController(t, idName)
	identityData := testutil.NewJwtIdentityData(idName, jwt)
	identityData.UseKeychain = true
	addResp := state.zetClient.AddIdentity(t, identityData)
	addResp.AssertSuccess()

	identityEvent := state.zetClient.WaitForIdentityEvent(t, "added", idName)
	require.True(t, identityEvent.Id.Active, "identity:added Active=%t", identityEvent.Id.Active)
	state.zetClient.WaitForControllerEvent(t, "connected", idName)
	keyRef := testutil.AssertKeychainKeyRef(t, identityEvent.Id.Identifier)
	t.Cleanup(func() { testutil.RemoveKeychainKey(t, keyRef) })
	require.True(t, testutil.KeychainKeyExists(t, keyRef), "private key %q should be in the OS keychain after enroll", keyRef)
	return identityEvent, keyRef
}

func forgetIdentityRemovesKey(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		identityEvent, keyRef := enrollWithKeychain(t, "test_keychain_forget")

		removeResp := state.zetClient.RemoveIdentity(t, identityEvent.Id.Identifier)
		removeResp.AssertSuccess()

		require.False(t, testutil.KeychainKeyExists(t, keyRef), "forget should remove key %q from the OS keychain", keyRef)
		require.NoFileExists(t, identityEvent.Id.Identifier, "forget should delete the identity file")
	})
}

func reEnrollSucceedsAfterReset(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		idName := "test_keychain_reenroll"
		identityEvent, _ := enrollWithKeychain(t, idName)

		removeResp := state.zetClient.RemoveIdentity(t, identityEvent.Id.Identifier)
		removeResp.AssertSuccess()

		state.overlay.ResetEnrollment(t, idName)
		enrollWithKeychain(t, idName)
	})
}
