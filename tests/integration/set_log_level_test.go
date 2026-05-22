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

func TestSetLogLevel(t *testing.T) {
	t.Run("succeeds", testSetLogLevelSucceeds)
}

func testSetLogLevelSucceeds(t *testing.T) {
	testutil.RunTestWithTimeout(t, func(t *testing.T) {
		client := testutil.OpenCommandPipe(t, state.zetClient)

		t.Logf("sending SetLogLevel %q", "trace")
		resp, err := client.SetLogLevel("trace")
		require.NoError(t, err, "failed to send SetLogLevel\n%s", state.zetClient.LogFile())
		require.True(t, resp.Success(), "SetLogLevel failed: error=%q code=%d", resp.Error, resp.Code)
		t.Logf("SetLogLevel succeeded: code=%d", resp.Code)
	})
}
