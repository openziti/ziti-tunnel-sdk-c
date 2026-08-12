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

func TestThirdPartyCa(t *testing.T) {
	t.Run("autocaEnrollCreatesIdentity", autocaEnrollCreatesIdentity)
	t.Run("ottcaEnrollsPreCreatedIdentity", ottcaEnrollsPreCreatedIdentity)
	t.Run("rejectsCertFromUnregisteredCa", rejectsCertFromUnregisteredCa)
	t.Run("rejectsAddingSameIdentityTwice", rejectsAddingSameIdentityTwice)
}

func autocaEnrollCreatesIdentity(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		caName := "test_tpca"
		caID := state.overlay.CreateThirdPartyCA(t, caName)
		commonName := "test_tpca_user1"
		cert, key := state.overlay.CreateClientCert(t, caName, commonName)
		caJwt := state.overlay.GetCaJwt(t, caID)

		// the controller names the auto-provisioned identity [caName]-[commonName]
		idName := caName + "-" + commonName
		identityData := testutil.NewCaIdentityData(idName, caJwt, cert, key)
		addResp := state.zetClient.AddIdentity(t, identityData)
		addResp.AssertSuccess()

		added := state.zetClient.WaitForIdentityEvent(t, "added", idName)
		require.True(t, added.Id.Active)
		state.zetClient.WaitForControllerEvent(t, "connected", idName)

		testutil.AssertValidJwtEnrolledIdentityFile(t, added.Id.Identifier)
		idFile := testutil.ReadIdentityFile(t, added.Id.Identifier)
		require.Equal(t, cert, idFile.ID.Cert)
		require.Equal(t, key, idFile.ID.Key)
	})
}

func ottcaEnrollsPreCreatedIdentity(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		caName := "test_tpca_ottca"
		state.overlay.CreateThirdPartyCA(t, caName)
		idName := "test_tpca_ottca_user1"
		ottcaJwt := state.overlay.CreateOttCaEnrollment(t, idName, caName)
		cert, key := state.overlay.CreateClientCert(t, caName, idName)

		identityData := testutil.NewCaIdentityData(idName, ottcaJwt, cert, key)
		addResp := state.zetClient.AddIdentity(t, identityData)
		addResp.AssertSuccess()

		added := state.zetClient.WaitForIdentityEvent(t, "added", idName)
		require.True(t, added.Id.Active)
		state.zetClient.WaitForControllerEvent(t, "connected", idName)

		testutil.AssertValidJwtEnrolledIdentityFile(t, added.Id.Identifier)
	})
}

func rejectsAddingSameIdentityTwice(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		caName := "test_tpca_dup"
		caID := state.overlay.CreateThirdPartyCA(t, caName)
		commonName := "test_tpca_dup_user1"
		cert, key := state.overlay.CreateClientCert(t, caName, commonName)
		caJwt := state.overlay.GetCaJwt(t, caID)

		idName := caName + "-" + commonName
		identityData := testutil.NewCaIdentityData(idName, caJwt, cert, key)
		addResp := state.zetClient.AddIdentity(t, identityData)
		addResp.AssertSuccess()
		state.zetClient.WaitForIdentityEvent(t, "added", idName)
		state.zetClient.WaitForControllerEvent(t, "connected", idName)

		dupResp := state.zetClient.AddIdentity(t, identityData)
		dupResp.AssertFail(500, "identity exists with the same name")
	})
}

func rejectsCertFromUnregisteredCa(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		caID := state.overlay.CreateThirdPartyCA(t, "test_tpca_neg")
		caJwt := state.overlay.GetCaJwt(t, caID)
		state.overlay.CreateLocalPkiCA(t, "test_tpca_unregistered")
		cert, key := state.overlay.CreateClientCert(t, "test_tpca_unregistered", "test_tpca_unregistered_user1")

		identityData := testutil.NewCaIdentityData("test_tpca_unregistered_user1", caJwt, cert, key)
		addResp := state.zetClient.AddIdentity(t, identityData)
		addResp.AssertFail(500, "key/cert are invalid")
	})
}
