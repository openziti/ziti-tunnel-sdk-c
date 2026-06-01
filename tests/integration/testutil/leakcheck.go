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
	"fmt"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TunnelerSnapshot is a point-in-time resource snapshot for one ZET process.
type TunnelerSnapshot struct {
	Label     string // ZET.Discriminator
	IpStats   TunnelIpStats
	ZitiConns []ZitiConnSummary
	Proc      ProcStats
}

// LeakHarness orchestrates resource snapshots around a data-path workload and
// asserts that counters return to their baseline after the workload completes.
// Use NewLeakHarness to construct; the zero value is not valid.
type LeakHarness struct {
	tunnelers        []*ZET
	clients          []*CommandsClient
	SettleTimeout    time.Duration // wait for non-TIME_WAIT TCP connections to drain (default 30s)
	UDPSettleTimeout time.Duration // wait for UDP PCBs to time out — UDP has no explicit close,
	// PCBs linger until a 30 s idle timer fires (default 35s)
	SettlePoll    time.Duration // polling interval during settle (default 500ms)
	FDTolerance   int           // allowed FD-count delta in either direction (default 2)
	PoolWhitelist []string      // lwIP pool names to assert on (e.g. "MEMP_PBUF_POOL")
}

// NewLeakHarness creates a LeakHarness for the given tunnelers. It dials a
// fresh IPC connection to each and registers Close as a t.Cleanup.
// pools is the list of lwIP pool names to assert on; pass nil to skip pool checks.
func NewLeakHarness(t *testing.T, tunnelers []*ZET, pools []string) *LeakHarness {
	t.Helper()
	h := &LeakHarness{
		tunnelers:        tunnelers,
		SettleTimeout:    30 * time.Second,
		UDPSettleTimeout: 35 * time.Second,
		SettlePoll:       500 * time.Millisecond,
		FDTolerance:      2,
		PoolWhitelist:    pools,
	}
	for _, z := range tunnelers {
		c, err := z.DialIPC()
		require.NoError(t, err, "leak harness: dial IPC for ZET %q", z.Discriminator)
		t.Cleanup(func() { _ = c.Close() })
		h.clients = append(h.clients, c)
	}
	return h
}

// Snapshot captures a TunnelerSnapshot for every tunneler in the harness.
func (h *LeakHarness) Snapshot(t *testing.T) []TunnelerSnapshot {
	t.Helper()
	snaps := make([]TunnelerSnapshot, len(h.tunnelers))
	for i, z := range h.tunnelers {
		s := TunnelerSnapshot{Label: z.Discriminator}

		if resp, err := h.clients[i].IpDump(""); err != nil {
			t.Logf("leakcheck[%s]: IpDump error: %v", z.Discriminator, err)
		} else if !resp.Success() {
			t.Logf("leakcheck[%s]: IpDump non-success: code=%d %s", z.Discriminator, resp.Code, resp.Error)
		} else {
			s.IpStats = resp.Data
		}

		if resp, err := h.clients[i].ZitiDump("", ""); err != nil {
			t.Logf("leakcheck[%s]: ZitiDump error: %v", z.Discriminator, err)
		} else if !resp.Success() {
			t.Logf("leakcheck[%s]: ZitiDump non-success: code=%d %s", z.Discriminator, resp.Code, resp.Error)
		} else {
			s.ZitiConns = ParseZitiDump(resp.Data)
		}

		if pid := z.Pid(); pid > 0 {
			if ps, err := SampleProcStats(pid); err != nil {
				t.Logf("leakcheck[%s]: SampleProcStats pid=%d: %v", z.Discriminator, pid, err)
			} else {
				s.Proc = ps
			}
		}

		snaps[i] = s
	}
	return snaps
}

// WaitForSettle polls until non-TIME_WAIT TCP connection counts have returned
// to their baseline levels, or SettleTimeout elapses. TCP connections require
// the underlay to close before lwIP frees the PCB, so a generous timeout is
// needed.
func (h *LeakHarness) WaitForSettle(t *testing.T, baseline []TunnelerSnapshot) {
	t.Helper()
	h.waitForProtoSettle(t, baseline, "tcp", h.SettleTimeout)
}

// waitForUDPSettle polls until UDP connection counts have returned to their
// baseline levels, or UDPSettleTimeout elapses. UDP PCBs have no explicit
// close; they linger until a ~30 s idle timer fires inside lwIP.
func (h *LeakHarness) waitForUDPSettle(t *testing.T, baseline []TunnelerSnapshot) {
	t.Helper()
	h.waitForProtoSettle(t, baseline, "udp", h.UDPSettleTimeout)
}

func (h *LeakHarness) waitForProtoSettle(t *testing.T, baseline []TunnelerSnapshot, proto string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		current := h.Snapshot(t)
		settled := true
		for i, s := range current {
			baseCnt := protoConnCount(baseline[i].IpStats.Connections, proto)
			currCnt := protoConnCount(s.IpStats.Connections, proto)
			if currCnt > baseCnt {
				log.Printf("leakcheck[%s]: waiting for %s settle: conns %d > baseline %d",
					h.tunnelers[i].Discriminator, proto, currCnt, baseCnt)
				settled = false
				break
			}
		}
		if settled {
			return
		}
		time.Sleep(h.SettlePoll)
	}
	t.Logf("leakcheck: %s settle timeout after %s; proceeding to assertion", proto, timeout)
}

// AssertNoLeak compares after against baseline and fails t for any detected leak.
func (h *LeakHarness) AssertNoLeak(t *testing.T, baseline, after []TunnelerSnapshot) {
	t.Helper()
	for i := range h.tunnelers {
		b := baseline[i]
		a := after[i]
		label := b.Label
		logFile := h.tunnelers[i].LogFile()

		// lwIP pool checks.
		for _, poolName := range h.PoolWhitelist {
			bUsed := poolUsed(b.IpStats.Pools, poolName)
			aUsed := poolUsed(a.IpStats.Pools, poolName)
			if aUsed != bUsed {
				t.Errorf("leakcheck[%s] pool %s: baseline Used=%d after Used=%d (delta=%+d)\n  log: %s",
					label, poolName, bUsed, aUsed, aUsed-bUsed, logFile)
			}
		}

		// TCP connection count: non-TIME_WAIT only. TIME_WAIT connections drain
		// on their own and are not counted as leaks.
		bTCP := protoConnCount(b.IpStats.Connections, "tcp")
		aTCP := protoConnCount(a.IpStats.Connections, "tcp")
		if aTCP != bTCP {
			t.Errorf("leakcheck[%s] tcp connections: baseline=%d after=%d\n%s\n  log: %s",
				label, bTCP, aTCP, formatConnList(a.IpStats.Connections, "tcp"), logFile)
		}

		// UDP connection count. UDP PCBs linger until the idle timer fires;
		// waitForUDPSettle must have elapsed before this assertion.
		bUDP := protoConnCount(b.IpStats.Connections, "udp")
		aUDP := protoConnCount(a.IpStats.Connections, "udp")
		if aUDP != bUDP {
			t.Errorf("leakcheck[%s] udp connections: baseline=%d after=%d\n%s\n  log: %s",
				label, bUDP, aUDP, formatConnList(a.IpStats.Connections, "udp"), logFile)
		}

		// Ziti connection count per identity.
		bMap := zitiConnMap(b.ZitiConns)
		aMap := zitiConnMap(a.ZitiConns)
		for id, aC := range aMap {
			bC := bMap[id]
			if aC.ActiveConns != bC.ActiveConns {
				t.Errorf("leakcheck[%s] ziti identity %q: baseline conns=%d after conns=%d\n  log: %s",
					label, id, bC.ActiveConns, aC.ActiveConns, logFile)
			}
			if aC.TotalRecvBuf > 0 {
				t.Errorf("leakcheck[%s] ziti identity %q: recv_buff not drained: total=%d\n  log: %s",
					label, id, aC.TotalRecvBuf, logFile)
			}
		}

		// FD count (within tolerance).
		if b.Proc.FDCount > 0 {
			delta := a.Proc.FDCount - b.Proc.FDCount
			if delta < 0 {
				delta = -delta
			}
			t.Logf("leakcheck[%s] fd: baseline=%d after=%d delta=%+d tolerance=%d",
				label, b.Proc.FDCount, a.Proc.FDCount, a.Proc.FDCount-b.Proc.FDCount, h.FDTolerance)
			if delta > h.FDTolerance {
				t.Errorf("leakcheck[%s] fd count: baseline=%d after=%d (delta=%+d, tolerance=%d)\n  log: %s",
					label, b.Proc.FDCount, a.Proc.FDCount, a.Proc.FDCount-b.Proc.FDCount, h.FDTolerance, logFile)
			}
		}
	}
}

// Run takes a baseline snapshot, executes workload, waits for TCP and then UDP
// connections to settle, then asserts no resource leaks.
func (h *LeakHarness) Run(t *testing.T, workload func()) {
	t.Helper()
	h.waitForIdle(t)
	baseline := h.Snapshot(t)
	workload()
	h.WaitForSettle(t, baseline)
	h.waitForUDPSettle(t, baseline)
	after := h.Snapshot(t)
	h.AssertNoLeak(t, baseline, after)
}

// waitForIdle waits until two consecutive snapshots show the same TCP and UDP
// connection counts, indicating the ZET has fully settled before the baseline
// is captured. This prevents probe connections from waitForTCPService or
// waitForUDPService from inflating the baseline.
func (h *LeakHarness) waitForIdle(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(h.SettleTimeout)
	var prev []TunnelerSnapshot
	for time.Now().Before(deadline) {
		current := h.Snapshot(t)
		if prev != nil && connCountsEqual(prev, current) {
			return
		}
		prev = current
		time.Sleep(h.SettlePoll)
	}
	t.Logf("leakcheck: idle wait timed out after %s; proceeding with baseline", h.SettleTimeout)
}

func connCountsEqual(a, b []TunnelerSnapshot) bool {
	for i := range a {
		if protoConnCount(a[i].IpStats.Connections, "tcp") != protoConnCount(b[i].IpStats.Connections, "tcp") {
			return false
		}
		if protoConnCount(a[i].IpStats.Connections, "udp") != protoConnCount(b[i].IpStats.Connections, "udp") {
			return false
		}
	}
	return true
}

// protoConnCount counts connections for the given protocol ("tcp" or "udp").
// For TCP, TIME_WAIT connections are excluded because they drain passively and
// are not leaks. UDP connections have no state so all are counted.
func protoConnCount(conns []IpStatsConn, proto string) int {
	n := 0
	for _, c := range conns {
		if c.Protocol != proto {
			continue
		}
		if proto == "tcp" && c.State == "TIME_WAIT" {
			continue
		}
		n++
	}
	return n
}

// formatConnList returns a human-readable listing of connections for proto,
// suitable for embedding in a test failure message.
func formatConnList(conns []IpStatsConn, proto string) string {
	var sb strings.Builder
	n := 0
	for _, c := range conns {
		if c.Protocol != proto {
			continue
		}
		fmt.Fprintf(&sb, "    %s %s:%d -> %s:%d state=%s service=%s\n",
			c.Protocol, c.LocalIP, c.LocalPort, c.RemoteIP, c.RemotePort, c.State, c.Service)
		n++
	}
	if n == 0 {
		return "    (none)"
	}
	return strings.TrimRight(sb.String(), "\n")
}

func poolUsed(pools []IpStatsPool, name string) int {
	for _, p := range pools {
		if p.Name == name {
			return p.Used
		}
	}
	return 0
}

func zitiConnMap(conns []ZitiConnSummary) map[string]ZitiConnSummary {
	m := make(map[string]ZitiConnSummary, len(conns))
	for _, c := range conns {
		m[c.Identifier] = c
	}
	return m
}
