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

func TestStatus(t *testing.T) {
	t.Run("hasExpectedTopLevelFields", testStatusHasExpectedTopLevelFields)
}

func testStatusHasExpectedTopLevelFields(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := testutil.DialIPC(ctx)
	require.NoError(t, err, "dial ZET IPC pipe")
	t.Cleanup(func() { _ = client.Close() })

	resp, err := client.Status(ctx)
	require.NoError(t, err, "Status send\n%s", zet.Logs())
	require.True(t, resp.Success, "Status failed: error=%q code=%d", resp.Error, resp.Code)

	var keys map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(resp.Data, &keys), "parse Status data: %s", resp.Data)

	require.Contains(t, keys, "Active", "Status.Active missing")
	require.Contains(t, keys, "Duration", "Status.Duration missing")
	require.Contains(t, keys, "StartTime", "Status.StartTime missing")
	require.Contains(t, keys, "Identities", "Status.Identities missing")
	require.Contains(t, keys, "IpInfo", "Status.IpInfo missing")
	require.Contains(t, keys, "LogLevel", "Status.LogLevel missing")
	require.Contains(t, keys, "ServiceVersion", "Status.ServiceVersion missing")
	require.Contains(t, keys, "TunIpv4", "Status.TunIpv4 missing")
	require.Contains(t, keys, "TunIpv4Mask", "Status.TunIpv4Mask missing")
	require.Contains(t, keys, "AddDns", "Status.AddDns missing")
	require.Contains(t, keys, "ApiPageSize", "Status.ApiPageSize missing")
	require.Contains(t, keys, "TunName", "Status.TunName missing")
	require.Contains(t, keys, "L2Enabled", "Status.L2Enabled missing")
	require.Contains(t, keys, "TapInfo", "Status.TapInfo missing")
	require.Len(t, keys, 14, "Status has unexpected key set: %v", keys)
}
