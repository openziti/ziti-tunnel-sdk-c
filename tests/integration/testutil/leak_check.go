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

package testutil

import (
	"encoding/json"
	"testing"
	"time"
)

const (
	leakPollInterval = 250 * time.Millisecond
	// UDP PCBs linger ~30s after last activity; 35s gives a 5s buffer.
	leakPollDeadline = 35 * time.Second
)

// IpBaseline holds lwip pool Used values captured before a data test runs.
type IpBaseline struct {
	PoolUsed map[string]int // pool name -> Used count at baseline
}

// CaptureIpBaseline dials the ZET's IPC and snapshots pool Used values.
func CaptureIpBaseline(t *testing.T, zet *ZET) IpBaseline {
	t.Helper()
	client, err := zet.DialIPC()
	if err != nil {
		t.Logf("CaptureIpBaseline: failed to dial IPC: %v", err)
		return IpBaseline{PoolUsed: map[string]int{}}
	}
	defer func() { _ = client.Close() }()

	resp := client.IpDump(t, "")
	baseline := IpBaseline{PoolUsed: make(map[string]int, len(resp.Data.Pools))}
	for _, pool := range resp.Data.Pools {
		baseline.PoolUsed[pool.Name] = pool.Used
	}
	return baseline
}

// AssertNoLeakedConnections polls ip_dump until the named service has no
// lingering connections (excluding TCP TIME_WAIT) and pool Used counts have
// not grown above the pre-test baseline, or the deadline is reached.
//
// Uses t.Errorf (not Fatalf) so both ZETs are checked even when one fails.
func AssertNoLeakedConnections(t *testing.T, zet *ZET, serviceName string, baseline IpBaseline) {
	t.Helper()
	deadline := time.Now().Add(leakPollDeadline)
	var lastStats IpStats

	for {
		client, err := zet.DialIPC()
		if err != nil {
			if time.Now().After(deadline) {
				t.Errorf("AssertNoLeakedConnections(%q): IPC unavailable at deadline: %v", serviceName, err)
				return
			}
			time.Sleep(leakPollInterval)
			continue
		}
		resp := client.IpDump(t, "")
		_ = client.Close()
		lastStats = resp.Data

		if noLeaks(lastStats, serviceName, baseline) {
			return
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(leakPollInterval)
	}

	statsJSON, _ := json.MarshalIndent(lastStats, "", "  ")
	t.Errorf("connection leak detected after test cleanup (service %q):\n%s", serviceName, string(statsJSON))

	client, err := zet.DialIPC()
	if err == nil {
		dumpResp := client.ZitiDump(t, "", "")
		_ = client.Close()
		dumpJSON, _ := json.MarshalIndent(dumpResp.Data, "", "  ")
		t.Logf("ZitiDump at leak detection:\n%s", string(dumpJSON))
	}
}

// noLeaks returns true when:
//  1. No active (non-TIME_WAIT) connections remain for the service.
//  2. Pool Used counts have not grown above baseline (TIME_WAIT TCP PCBs are excluded).
func noLeaks(stats IpStats, serviceName string, baseline IpBaseline) bool {
	timeWaitCount := 0
	for _, c := range stats.Connections {
		if c.Service == serviceName && c.Protocol == "tcp" && c.State == "TIME_WAIT" {
			timeWaitCount++
		}
	}

	for _, c := range stats.Connections {
		if c.Service != serviceName {
			continue
		}
		if c.Protocol == "tcp" && c.State == "TIME_WAIT" {
			continue
		}
		return false
	}

	for _, pool := range stats.Pools {
		base, ok := baseline.PoolUsed[pool.Name]
		if !ok {
			continue
		}
		effectiveUsed := pool.Used
		if pool.Name == "MEMP_TCP_PCB" {
			effectiveUsed -= timeWaitCount
		}
		if effectiveUsed > base {
			return false
		}
	}

	return true
}
