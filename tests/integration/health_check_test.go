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
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/openziti/ziti-tunnel-sdk-c/tests/integration/testutil"
	"github.com/stretchr/testify/require"
)

// These tests exercise host.v1 portChecks/httpChecks end to end: a single ZET hosts a
// service whose config declares checks, and the tests observe the resulting terminator
// state (cost/precedence) at the controller as the checked backend fails and recovers.
// There is no dial/intercept side and no data-plane traffic -- the terminator's cost and
// precedence, both persisted controller-side fields (see testutil.Terminator), are the
// direct, intended result of ziti_update_terminator() and prove the whole path (SDK ->
// tunneler health check engine -> edge router -> controller) end to end on their own.
//
// This assumes the ZET under test supports host.v1 health checks; there is no
// version-capability gate for it (unlike requireMultiTunnel) since the feature has no
// released version yet to gate on. Against an older ZET, portChecks/httpChecks are
// silently ignored (see ziti-sdk-c's ZITI_HOST_CFG_V1_MODEL), so these tests will just
// time out waiting for a terminator state that never arrives.

// healthCheckResourceNames holds the controller-side resource names for one health
// check test scenario.
type healthCheckResourceNames struct {
	identity   string
	hostConfig string
	service    string
	bindPolicy string
}

func newHealthCheckNames(t *testing.T) healthCheckResourceNames {
	base := strings.ReplaceAll(t.Name(), "/", "-")
	return healthCheckResourceNames{
		identity:   base + "-host-id",
		hostConfig: base + "-host-cfg",
		service:    base + "-svc",
		bindPolicy: base + "-bind",
	}
}

// setupHealthCheckService creates a host.v1 service (with the given listenOptions and
// checks) hosted by a single ZET, and registers cleanup. Unlike setupT2TService there is
// no intercept side: these tests never dial the service, only observe its terminator.
func setupHealthCheckService(
	t *testing.T,
	hostZET *testutil.ZET,
	names healthCheckResourceNames,
	protocol, forwardAddr string,
	forwardPort int,
	cost int,
	precedence string,
	portChecks []testutil.PortCheckSpec,
	httpChecks []testutil.HttpCheckSpec,
) {
	t.Helper()
	overlay := state.overlay

	hostJWT, err := overlay.CreateIdentityJWT(names.identity)
	require.NoError(t, err, "create host identity JWT")

	hostClient, err := hostZET.DialIPC()
	require.NoError(t, err, "dial host ZET IPC")
	t.Cleanup(func() { _ = hostClient.Close() })

	resp := hostClient.AddIdentity(t, testutil.AddIdentityData{
		IdentityFilename: names.identity,
		JwtContent:       &hostJWT,
	})
	require.True(t, resp.Success, "AddIdentity to host ZET failed: %s\n%s", resp.Error, hostZET.LogFile())

	require.NoError(t, overlay.CreateHostConfigV1WithChecks(names.hostConfig, protocol, forwardAddr, forwardPort,
		cost, precedence, portChecks, httpChecks), "create host config")
	require.NoError(t, overlay.CreateService(names.service, []string{names.hostConfig}), "create service")
	require.NoError(t, overlay.CreateBindServicePolicy(names.bindPolicy, names.identity, names.service),
		"create bind policy")

	t.Cleanup(func() {
		hostClient.RemoveIdentity(t, names.identity)
		_ = overlay.DeleteServicePolicy(names.bindPolicy)
		_ = overlay.DeleteService(names.service)
		_ = overlay.DeleteConfig(names.hostConfig)
	})
}

// splitPort parses the port out of a "host:port" address as an int, failing the test on
// a malformed address.
func splitPort(t *testing.T, addr string) int {
	t.Helper()
	_, portStr, err := net.SplitHostPort(addr)
	require.NoError(t, err, "parse addr %s", addr)
	var port int
	_, err = fmt.Sscanf(portStr, "%d", &port)
	require.NoError(t, err, "parse port from %s", addr)
	return port
}

// anyTerminator matches the first terminator seen for a service, regardless of state --
// used to wait for the initial bind, before any check result has had a chance to move
// cost/precedence away from baseline.
func anyTerminator(testutil.Terminator) bool { return true }

// TestHealthCheckPortCheckFailAndRecover hosts a TCP service with a portCheck against
// its own backend. Taking the backend down should mark the terminator's precedence
// "failed"; bringing it back should return it to "default".
func TestHealthCheckPortCheckFailAndRecover(t *testing.T) {
	testutil.RunWithTimeoutOf(t, 70*time.Second, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		backend := testutil.StartTCPBackend(t)
		port := splitPort(t, backend.Addr())

		names := newHealthCheckNames(t)
		setupHealthCheckService(t, state.zetClient, names, "tcp", "127.0.0.1", port,
			0, "",
			[]testutil.PortCheckSpec{{
				Address:  backend.Addr(),
				Interval: "250ms",
				Timeout:  "250ms",
				Actions: []testutil.HealthCheckAction{
					{Trigger: "fail", Action: "mark unhealthy"},
					{Trigger: "pass", Action: "mark healthy"},
				},
			}},
			nil,
		)

		bindCtx, bindCancel := context.WithTimeout(ctx, 30*time.Second)
		defer bindCancel()
		term := state.overlay.WaitForTerminator(t, bindCtx, names.service, anyTerminator)
		require.Equal(t, "default", term.Precedence, "terminator should start at default precedence")

		backend.Stop()
		failCtx, failCancel := context.WithTimeout(ctx, 30*time.Second)
		defer failCancel()
		state.overlay.WaitForTerminator(t, failCtx, names.service, func(term testutil.Terminator) bool {
			return term.Precedence == "failed"
		})

		backend.Start()
		recoverCtx, recoverCancel := context.WithTimeout(ctx, 30*time.Second)
		defer recoverCancel()
		state.overlay.WaitForTerminator(t, recoverCtx, names.service, func(term testutil.Terminator) bool {
			return term.Precedence == "default"
		})
	})
}

// TestHealthCheckPortCheckCostRatchet hosts a TCP service whose portCheck increases
// cost on each failed interval and decreases it on each passing one. A sustained outage
// should push cost above baseline by more than one interval's worth (proving
// accumulation, not a one-shot bump); recovery should walk it back down to exactly the
// baseline, never below.
func TestHealthCheckPortCheckCostRatchet(t *testing.T) {
	testutil.RunWithTimeoutOf(t, 100*time.Second, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()

		backend := testutil.StartTCPBackend(t)
		port := splitPort(t, backend.Addr())

		const baselineCost = 10
		const step = 20

		names := newHealthCheckNames(t)
		setupHealthCheckService(t, state.zetClient, names, "tcp", "127.0.0.1", port,
			baselineCost, "default",
			[]testutil.PortCheckSpec{{
				Address:  backend.Addr(),
				Interval: "250ms",
				Timeout:  "250ms",
				Actions: []testutil.HealthCheckAction{
					{Trigger: "fail", Action: fmt.Sprintf("increase cost %d", step)},
					{Trigger: "pass", Action: fmt.Sprintf("decrease cost %d", step)},
				},
			}},
			nil,
		)

		bindCtx, bindCancel := context.WithTimeout(ctx, 30*time.Second)
		defer bindCancel()
		term := state.overlay.WaitForTerminator(t, bindCtx, names.service, anyTerminator)
		require.Equal(t, baselineCost, term.Cost, "terminator should start at baseline cost")

		backend.Stop()
		riseCtx, riseCancel := context.WithTimeout(ctx, 30*time.Second)
		defer riseCancel()
		state.overlay.WaitForTerminator(t, riseCtx, names.service, func(term testutil.Terminator) bool {
			return term.Cost >= baselineCost+2*step
		})

		backend.Start()
		recoverCtx, recoverCancel := context.WithTimeout(ctx, 30*time.Second)
		defer recoverCancel()
		state.overlay.WaitForTerminator(t, recoverCtx, names.service, func(term testutil.Terminator) bool {
			return term.Cost == baselineCost
		})
	})
}

// TestHealthCheckHTTPCheckStatusAndBody hosts a TCP service (unrelated to the check
// itself) alongside an httpCheck against a separate HTTP backend. The check's
// expectStatus/expectInBody gate whether it passes; flipping the backend's response
// should fail it and recover it the same way the portCheck tests do for a TCP dial.
func TestHealthCheckHTTPCheckStatusAndBody(t *testing.T) {
	testutil.RunWithTimeoutOf(t, 70*time.Second, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		backend := testutil.StartHTTPBackend(t)
		backend.SetResponse(200, "healthy")
		port := splitPort(t, backend.Addr())

		names := newHealthCheckNames(t)
		setupHealthCheckService(t, state.zetClient, names, "tcp", "127.0.0.1", port,
			0, "",
			nil,
			[]testutil.HttpCheckSpec{{
				URL:          "http://" + backend.Addr() + "/healthz",
				Interval:     "250ms",
				Timeout:      "250ms",
				ExpectStatus: 200,
				ExpectInBody: "healthy",
				Actions: []testutil.HealthCheckAction{
					{Trigger: "fail", Action: "mark unhealthy"},
					{Trigger: "pass", Action: "mark healthy"},
				},
			}},
		)

		bindCtx, bindCancel := context.WithTimeout(ctx, 30*time.Second)
		defer bindCancel()
		state.overlay.WaitForTerminator(t, bindCtx, names.service, func(term testutil.Terminator) bool {
			return term.Precedence == "default"
		})

		// wrong status and body: the check should fail on both grounds
		backend.SetResponse(500, "down")
		failCtx, failCancel := context.WithTimeout(ctx, 30*time.Second)
		defer failCancel()
		state.overlay.WaitForTerminator(t, failCtx, names.service, func(term testutil.Terminator) bool {
			return term.Precedence == "failed"
		})

		// status matches again but body doesn't: still failing
		backend.SetResponse(200, "not what you expected")
		stillFailCtx, stillFailCancel := context.WithTimeout(ctx, 15*time.Second)
		defer stillFailCancel()
		state.overlay.WaitForTerminator(t, stillFailCtx, names.service, func(term testutil.Terminator) bool {
			return term.Precedence == "failed"
		})

		// both match again: recovers
		backend.SetResponse(200, "healthy")
		recoverCtx, recoverCancel := context.WithTimeout(ctx, 30*time.Second)
		defer recoverCancel()
		state.overlay.WaitForTerminator(t, recoverCtx, names.service, func(term testutil.Terminator) bool {
			return term.Precedence == "default"
		})
	})
}
