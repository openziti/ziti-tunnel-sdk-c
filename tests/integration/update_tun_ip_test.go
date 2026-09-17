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
)

func TestUpdateTunIP(t *testing.T) {
	t.Run("withPrefixAndNoIpRejected", withPrefixAndNoIpRejected)
}

// A prefix with no tun IP used to crash the daemon (strdup(NULL) before the null
// check). It must now be rejected with the daemon still up.
func withPrefixAndNoIpRejected(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		resp := state.zetClient.UpdateTunIPv4(t, testutil.TunIPv4Data{TunPrefixLength: 16})
		resp.AssertFail(500, "Tun IP is null")
	})
}
