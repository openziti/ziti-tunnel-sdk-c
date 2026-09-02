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
	"time"

	"github.com/openziti/ziti-tunnel-sdk-c/tests/integration/testutil"
	"github.com/stretchr/testify/require"
)

const appInfoTestTimeout = 30 * time.Second

// Authentication is what writes sdkInfo, so this reads the identity back from the controller rather
// than trusting what ZET reports about itself. The suite runs ZET standalone, so the Windows service
// path is out of reach here and is covered by the registry-level tests.
func TestAppInfo(t *testing.T) {
	testutil.RunWithTimeoutOf(t, appInfoTestTimeout, func(t *testing.T) {
		const idName = "test_app_info"
		zet := state.zetClient

		require.NotEmpty(t, zet.Version, "ZET version not probed; ProbeVersion must run before this test")

		testutil.FetchAndEnrollJwt(t, state.overlay, zet, idName)

		sdkInfo := state.overlay.GetSdkInfo(t, idName)
		require.Equal(t, "ziti-edge-tunnel", sdkInfo.AppId,
			"standalone appId must be the fixed string, not argv[0]")
		require.Equal(t, zet.Version, sdkInfo.AppVersion,
			"standalone appVersion must be the tunneler's own version")
	})
}
