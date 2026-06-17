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
	t.Run("enrollmentSucceeds", enrollmentSucceeds)
	t.Run("forgetIdentityRemovesKey", forgetIdentityRemovesKey)
}

// enrollWithKeychain enrolls idName with UseKeychain, asserts the key is a keychain
// ref, registers cleanup of the OS keystore key, and returns the added event and ref.
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
	return identityEvent, keyRef
}

func enrollmentSucceeds(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		_, keyRef := enrollWithKeychain(t, "test_keychain_enroll")

		require.True(t, testutil.KeychainKeyExists(t, keyRef), "private key %q should be in the OS keychain after enroll", keyRef)
	})
}

func forgetIdentityRemovesKey(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		identityEvent, keyRef := enrollWithKeychain(t, "test_keychain_forget")
		require.True(t, testutil.KeychainKeyExists(t, keyRef), "private key %q should exist before forget", keyRef)

		removeResp := state.zetClient.RemoveIdentity(t, identityEvent.Id.Identifier)
		removeResp.AssertSuccess()

		require.False(t, testutil.KeychainKeyExists(t, keyRef), "forget should remove key %q from the OS keychain", keyRef)
	})
}
