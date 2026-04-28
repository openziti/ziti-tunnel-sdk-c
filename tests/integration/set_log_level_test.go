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
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/openziti/ziti-tunnel-sdk-c/tests/integration/testutil"
	"github.com/stretchr/testify/require"
)

func TestSetLogLevel(t *testing.T) {
	t.Run("changesLogLevelInStatus", testSetLogLevelChangesLogLevelInStatus)
}

func testSetLogLevelChangesLogLevelInStatus(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := testutil.DialIPC(ctx)
	require.NoError(t, err, "dial ZET IPC pipe")
	t.Cleanup(func() { _ = client.Close() })

	setResp, err := client.SetLogLevel(ctx, "trace")
	require.NoError(t, err, "SetLogLevel send\n%s", zet.Logs())
	require.True(t, setResp.Success, "SetLogLevel failed: error=%q code=%d", setResp.Error, setResp.Code)
	t.Logf("SetLogLevel(trace) succeeded: code=%d", setResp.Code)

	statusResp, err := client.Status(ctx)
	require.NoError(t, err, "Status send\n%s", zet.Logs())
	require.True(t, statusResp.Success, "Status failed: error=%q code=%d", statusResp.Error, statusResp.Code)

	var status struct {
		LogLevel string `json:"LogLevel"`
	}
	require.NoError(t, json.Unmarshal(statusResp.Data, &status), "parse Status: %s", statusResp.Data)
	require.Equal(t, "trace", status.LogLevel, "Status.LogLevel should reflect SetLogLevel")
	t.Logf("Status.LogLevel after SetLogLevel: %q", status.LogLevel)
}
