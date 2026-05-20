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
	"encoding/json"
	"testing"

	"github.com/openziti/ziti-tunnel-sdk-c/tests/integration/testutil"
	"github.com/stretchr/testify/require"
)

func TestSetLogLevel(t *testing.T) {
	testutil.RunTestWithTimeout(t, "changesLogLevelInStatus", testSetLogLevelChangesLogLevelInStatus)
}

func testSetLogLevelChangesLogLevelInStatus(t *testing.T) {
	client := testutil.OpenCommandPipe(t, state.zetClient)

	t.Logf("sending SetLogLevel %q", "trace")
	setResp, err := client.SetLogLevel("trace")
	require.NoError(t, err, "failed to send SetLogLevel\n%s", state.zetClient.LogFile())
	require.True(t, setResp.Success, "SetLogLevel failed: error=%q code=%d", setResp.Error, setResp.Code)
	t.Logf("SetLogLevel succeeded")

	t.Logf("fetching Status to verify LogLevel change took effect")
	statusResp, err := client.Status()
	require.NoError(t, err, "failed to send Status\n%s", state.zetClient.LogFile())
	require.True(t, statusResp.Success, "Status failed: error=%q code=%d", statusResp.Error, statusResp.Code)

	var status struct {
		LogLevel string `json:"LogLevel"`
	}
	require.NoError(t, json.Unmarshal(statusResp.Data, &status), "parse Status: %s", statusResp.Data)
	require.Equal(t, "trace", status.LogLevel, "Status.LogLevel should reflect SetLogLevel")
	t.Logf("Status.LogLevel after SetLogLevel: %q", status.LogLevel)
}
