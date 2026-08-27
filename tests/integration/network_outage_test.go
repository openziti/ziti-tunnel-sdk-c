//go:build slowtests

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

// Sits behind the slowtests tag (nightly, or locally via
// `go test -tags slowtests -config config.json`) because it stands up its
// own quickstart controller and its sever window alone must run several
// minutes to outlast the shortened session/token lifetime.

package integration_test

import (
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openziti/ziti-tunnel-sdk-c/tests/integration/testutil"
	"github.com/stretchr/testify/require"
)

const (
	// The outage proxy sits at outageOverlayCtrlPort - the port everything
	// (this harness's own ziti CLI calls, ZET) dials, and the same one
	// embedded in enrollment JWTs / "/controllers" HA-endpoint-list
	// responses, since edge.api.address is pointed there too (see
	// testutil.Overlay.BindCtrlPort). The controller itself actually binds
	// outageOverlayBindCtrlPort, a port nothing ever dials directly.
	// Different from the shared overlay's 1280/3022 so both can run at once.
	outageOverlayCtrlPort     = 11280
	outageOverlayBindCtrlPort = 21280
	outageOverlayRtrPort      = 13022

	// The credential that must expire differs by auth path:
	//   - OIDC: edge.api.sessionTimeout does NOT apply - an OIDC identity's
	//     session lifetime is edge.oidc.accessTokenDuration/refreshTokenDuration
	//     instead (30m/24h defaults, no line in the generated config to edit in
	//     place - see testutil.PreconfigureOidcTokenDurations). accessTokenDuration
	//     must be >= 1m; refreshTokenDuration must be >= accessTokenDuration + 1m
	//     or the controller silently corrects it back toward the default.
	//   - Legacy: edge.api.sessionTimeout is the right (and only) knob - see
	//     testutil.PreconfigureSessionTimeout.
	// outageExpiryWindow is used as refreshTokenDuration for OIDC or
	// sessionTimeout for Legacy; both represent "how long before the
	// credential that gates reconnect expires."
	outageAccessTokenDuration = 1 * time.Minute
	outageExpiryWindow        = 3 * time.Minute
	// Comfortably longer than outageExpiryWindow so the credential has
	// actually expired server-side by the time the network heals - this is
	// what distinguishes the scenario from a shorter, still-valid outage.
	outageSeverDuration = outageExpiryWindow + 90*time.Second
	// How long to stay connected and healthy before severing - just enough
	// for the initial connect to be confirmed stable, not tuned to accumulate
	// refresh cycles (see the doc comment below for why: outageSeverDuration
	// always outlasts outageExpiryWindow regardless of this value, so restore
	// forces a full re-auth either way - the number of refresh cycles before
	// the sever isn't what selects which bug fires).
	outagePreSeverSettleDuration = 60 * time.Second
	// Bound on just the post-restore reconnect wait, so a stuck-forever regression
	// fails fast with a specific message instead of the generic outageTestTimeout.
	outageRecoveryTimeout = 3 * time.Minute
	// How long to watch the reconnect for an immediate flap before trusting it.
	// Belt-and-suspenders alongside the proxy-only address below: a stray
	// fallback connection would be expected to flap almost immediately, not
	// stay up for several seconds.
	outageSettleWindow = 10 * time.Second
	// Dedicated-overlay setup + outagePreSeverSettleDuration + outageSeverDuration
	// + outageRecoveryTimeout + outageSettleWindow, plus slack. Pass a matching
	// -timeout to `go test` itself (its own default is 10m and would kill the
	// process with a less useful goroutine dump before this fires).
	outageTestTimeout = 25 * time.Minute
	// Forces a service-refresh (and so a fresh reconnect attempt) about once a
	// second instead of ZET's default 10s, so outageRecoveryTimeout only has
	// to be long enough for real timeouts to elapse a handful of times, not
	// long enough to also cover a slow retry cadence on top of that. See the
	// doc comment above for why cycle count itself turned out not to matter.
	outageRefreshIntervalArg = "1"
)

// TestOutageRecoveryAfterSessionExpiry drives ZET through a real
// credential-expiring network outage: stand up a dedicated quickstart
// controller (not the shared one - see below) already configured, before
// its first real start, so it only ever advertises a relay's address rather
// than its own; shorten its session/token lifetime for whichever auth path
// this run is configured for; sever that relay for longer than the
// credential's lifetime so it actually expires server-side; then restore
// the network and assert ZET re-authenticates, reconnects, and stays
// connected. Runs against both the OIDC and Legacy paths (nightly's
// main/main-ha and main-legacy-auth topologies).
//
// This is a regression guard for
// https://openziti.discourse.group/t/zet-does-not-recover-after-prolonged-controller-network-outage-once-api-session-expires/5993
// - ziti-edge-tunnel getting permanently stuck in an unauthenticated retry
// loop after a prolonged outage, only recovering on a manual restart. The
// confirmed root cause is https://github.com/openziti/tlsuv/pull/367 (tlsuv's
// OpenSSL/BoringSSL set_own_cert misuse on the SSL_CTX), fixed in tlsuv
// v0.42.4 / ziti-sdk-c 1.18.6+.
//
// Getting this test to actually reproduce the bug took several wrong turns,
// worth recording so they don't get re-tried:
//   - Cycle count/exposure time is NOT what selects it. An earlier version of
//     this test used a 10-minute pre-sever settle window on the theory that
//     the bug needed many accumulated refresh cycles to manifest (real field
//     reports took hours). That theory was wrong: outagePreSeverSettleDuration
//     is now a minimal 60s (just enough to confirm the initial connect is
//     stable) and the bug still reproduces reliably.
//   - What actually matters is how OutageProxy models the outage. It
//     originally simulated Sever by actively resetting every connection
//     (SO_LINGER=0 + Close) - fast, clean, deterministic feedback to the
//     client. That turned out to be the problem: a client that gets an
//     immediate RST recovers too cleanly to ever hit the bug. Confirmed by a
//     side-by-side comparison against a podman container with its network
//     interface disabled (a genuine black hole, no RST) - 1.18.5 (pre-fix)
//     reliably failed to recover against the container, but passed against
//     this proxy's old RST-based Sever every time. OutageProxy now
//     black-holes instead (see its own doc comment) - bytes just stop moving,
//     no RST/FIN, so the client only finds out via its own read/write
//     timeouts, same as a real partition. With that change, 1.18.5 reliably
//     times out in outageRecoveryTimeout and 1.18.7 reliably recovers
//     (slower than the old RST-based proxy - tens of seconds to over a
//     minute, since real timeouts have to elapse - but well within budget).
//   - A separate, still-open bug exists too: when a full OIDC re-auth attempt
//     itself fails (not just a token refresh), oidc_auth_token_cb's
//     OIDC_TOKEN_FAILED case (library/oidc.c) reports
//     ZitiAuthStateUnauthenticated, and ztx_set_unauthenticated()
//     (library/ziti.c) tears down session state but arms no retry/reschedule
//     on that specific path - confirmed live against a real, permanently-
//     stuck field specimen. This test does not appear to hit it: the -r 1
//     flag (see outageRefreshIntervalArg) forces a service-refresh cycle
//     every second, and that cycle independently re-triggers a fresh full
//     OIDC attempt each time regardless of what ztx_set_unauthenticated did
//     or didn't arm, which is likely why 1.18.5's failures here are
//     "retries forever, never succeeds" rather than "stops retrying
//     entirely." If a future run ever shows retry activity actually stopping
//     before outageRecoveryTimeout elapses, that's this bug, not tlsuv#367.
//
// Uses its own controller rather than the shared state.overlay, and needs
// edge.api.address itself redirected to the proxy (testutil.Overlay.BindCtrlPort),
// not just the identity file's ztAPI - both confirmed necessary the hard way:
//   - Identity-file-only redirection isn't enough: ZET's own log showed live
//     requests against the real controller address while the proxy was
//     actively severed. A single-node quickstart still reports itself in
//     "/controllers" HA-endpoint-list responses, so any client that has ever
//     received one (including this test's own pre-sever connect) learns the
//     real address and fails over to it directly once the proxied connection
//     drops, bypassing the sever entirely.
//   - Redirecting edge.api.address on the shared controller would risk the
//     long-running zetClient/zetHost also learning and dialing the temporary
//     proxy address, hence the dedicated controller.
//   - The controller validates incoming requests' Host header against its
//     own configured address, so simply pointing that address at the proxy
//     while still binding/dialing the real port directly (for this harness's
//     own admin CLI calls) breaks every such direct call - discovered as a
//     redirect-URI 404 on admin login. BindCtrlPort resolves this: the proxy
//     occupies the address everything (including admin CLI calls) actually
//     dials, and the real controller binds a port nothing dials directly.
//   - That, in turn, means the address has to be correct *before* the first
//     real start - every restart's own readiness check dials through the
//     proxy, so a start against a config that doesn't yet advertise the
//     proxy's address breaks its own admin login. Hence
//     GenerateConfig+Preconfigure* instead of Start+Set*: configure fully
//     via a throwaway `--configure-and-exit` run first, then start for real
//     exactly once.
//
// Deliberately does not wait for a "disconnected" controller event after
// severing: that event is tied to ziti-sdk-c's own auth-context transitions
// (TunnelEvent_ContextEvent), not to generic connectivity loss, and isn't
// guaranteed to fire for every background reconnect failure during an
// outage - waiting on it hung for the full outageTestTimeout in practice.
// Waits for the edge router control channel's own "connected" event after
// restore rather than the controller's (see WaitForRouterEvent's doc comment
// for why) - every other suite here relies on the weaker controller signal,
// which is fine for an initial connect but was observed firing (and then
// immediately flapping) as a false positive during recovery from this exact
// kind of outage.

// keepArtifacts, if set via ZITI_OUTAGE_KEEP_ARTIFACTS, leaves the dedicated
// overlay and zetOutage processes running (and their logs/identities on disk
// at a fixed path, not a t.TempDir() that gets removed regardless) after the
// test concludes, so a hang can be inspected live (lldb/sample) instead of
// only having the ~10s flap-check window before normal cleanup kills
// everything. Debugging aid only - unset for a real test run.
var keepArtifacts = os.Getenv("ZITI_OUTAGE_KEEP_ARTIFACTS") != ""

// outageArtifactDir is t.TempDir(), or a fixed, freshly-emptied directory
// under keepArtifacts so it survives this process exiting.
func outageArtifactDir(t *testing.T, name string) string {
	t.Helper()
	if !keepArtifacts {
		return t.TempDir()
	}
	dir := filepath.Join(os.TempDir(), "ziti-outage-debug", name)
	require.NoError(t, os.RemoveAll(dir), "clear stale debug artifact dir %s", dir)
	require.NoError(t, os.MkdirAll(dir, 0o755), "create debug artifact dir %s", dir)
	log.Printf("outage test: ZITI_OUTAGE_KEEP_ARTIFACTS set - %s will survive this run, and its process will not be stopped", dir)
	return dir
}

func TestOutageRecoveryAfterSessionExpiry(t *testing.T) {
	testutil.RunWithTimeoutOf(t, outageTestTimeout, func(t *testing.T) {
		overlay := &testutil.Overlay{
			ZitiBin:            state.overlay.ZitiBin,
			Home:               filepath.Join(outageArtifactDir(t, "overlay"), "overlay"),
			ControllerUser:     state.overlay.ControllerUser,
			ControllerPassword: state.overlay.ControllerPassword,
			Auth:               state.overlay.Auth,
			CtrlPort:           outageOverlayCtrlPort,
			BindCtrlPort:       outageOverlayBindCtrlPort,
			RtrPort:            outageOverlayRtrPort,
			Done:               make(chan error, 1),
		}
		if !keepArtifacts {
			t.Cleanup(overlay.Stop) // safe no-op if Start never succeeds
		}

		require.NoError(t, overlay.GenerateConfig(), "generate outage overlay config")

		switch overlay.Auth {
		case testutil.AuthOIDC:
			overlay.PreconfigureOidcTokenDurations(t, outageAccessTokenDuration, outageExpiryWindow)
		case testutil.AuthLegacy:
			overlay.PreconfigureDisableOidc(t)
			overlay.PreconfigureSessionTimeout(t, outageExpiryWindow)
		default:
			t.Fatalf("unknown ziti.auth %q", overlay.Auth)
		}

		proxy := testutil.StartOutageProxy(t,
			fmt.Sprintf("127.0.0.1:%d", outageOverlayCtrlPort),
			fmt.Sprintf("localhost:%d", outageOverlayBindCtrlPort))
		overlay.PreconfigureEdgeApiAddress(t, proxy.Addr)

		require.NoError(t, overlay.Start(), "start outage overlay")

		zet := &testutil.ZET{
			BinPath:       state.zetClient.BinPath,
			Discriminator: "zetOutage",
			RootDir:       outageArtifactDir(t, "zet"),
			Verbosity:     state.zetClient.Verbosity,
			ExtraArgs:     []string{"-r", outageRefreshIntervalArg},
			DetachSession: keepArtifacts,
		}
		require.NoError(t, zet.Start())
		if !keepArtifacts {
			// t.Cleanup, not defer: if the recovery wait below ever hangs instead of
			// returning (e.g. a bug in this test itself), a plain defer here would
			// never run - it's registered on this goroutine, which RunWithTimeoutOf
			// abandons rather than unwinds once its own outer timeout fires.
			// t.Cleanup runs regardless, once the test concludes.
			t.Cleanup(zet.Stop)
		}

		const idName = "test_outage_recovery"
		jwt, err := overlay.CreateIdentityJWT(idName)
		require.NoError(t, err, "create identity %s", idName)
		added := testutil.EnrollJwt(t, zet, idName, jwt)
		zet.WaitForControllerEvent(t, "connected", idName)
		log.Printf("outage test: initial connect confirmed for %s", idName)

		// Belt-and-suspenders: redirect the identity's own on-disk ztAPI too, in
		// case enrollment ever embeds a different address than the configured
		// edge.api.address. Stop first: ZET rewrites its own identity file
		// around connect events, so doctoring it while the process is still
		// running races that.
		zet.Stop()
		redirectIdentityThroughOutageProxy(t, added.Id.Identifier, proxy.Addr)
		require.NoError(t, zet.Start(), "restart zet after redirect\n%s", zet.LogFile())
		zet.WaitForControllerEvent(t, "connected", idName)
		log.Printf("outage test: connect-through-proxy confirmed for %s", idName)

		log.Printf("outage test: staying connected for %s before severing, so several real access-token "+
			"refresh cycles (~1/%s) elapse first", outagePreSeverSettleDuration, outageAccessTokenDuration)
		for remaining := outagePreSeverSettleDuration; remaining > 0; {
			step := time.Minute
			if remaining < step {
				step = remaining
			}
			time.Sleep(step)
			remaining -= step
			log.Printf("outage test: settling, %s remaining before sever", remaining)
		}

		log.Printf("outage test: severing network to the controller for %s (auth=%s, expiry window %s)", outageSeverDuration, overlay.Auth, outageExpiryWindow)
		proxy.Sever()

		log.Printf("outage test: sleeping %s so the session/token actually expires server-side", outageSeverDuration)
		time.Sleep(outageSeverDuration)

		log.Printf("outage test: restoring network to the controller; waiting up to %s for reconnect", outageRecoveryTimeout)
		proxy.Restore()

		// SkipToNow is required, not just tidy: nothing before this point ever
		// waits for a router event (only the pre-sever controller "connected"
		// checks), so the router's own initial "connected"/"added" events from
		// the very first connect - and its mid-outage "disconnected" - are
		// still sitting unconsumed in the buffer. Without this, the waits
		// below would match those stale events instantly instead of waiting
		// for anything that actually happens after restore - see
		// EventClient.SkipToNow's doc comment; this is exactly how the
		// "flap" this test used to report turned out to be fake.
		zet.SkipToNow()

		// Deliberately not gating on the controller "connected" event here: it
		// fires the moment any single controller HTTP call succeeds (see
		// WaitForControllerEvent's doc comment) regardless of the edge router
		// control channel's own state, and was observed firing (and then
		// immediately flapping) while the router channel was still stuck
		// "not fully authenticated" - a false-positive recovery signal. The
		// router channel is what's actually gated behind a full re-auth
		// (channel.c reconnect_cb) and what the regression this test guards
		// against leaves permanently stuck, so it's the signal to trust.
		ev, ok := zet.WaitForRouterEventWithin(t, "connected", idName, outageRecoveryTimeout)
		require.True(t, ok, "the edge router control channel did not reconnect within %s of the network being restored - "+
			"this is the regression this test guards against (see the doc comment above)", outageRecoveryTimeout)
		log.Printf("outage test: reconnected after restore: %+v; watching %s for an immediate flap", ev, outageSettleWindow)

		_, flapped := zet.WaitForRouterEventWithin(t, "disconnected", idName, outageSettleWindow)
		require.False(t, flapped, "edge router disconnected again within %s of reconnecting - the reconnect was not stable", outageSettleWindow)
		log.Printf("outage test: reconnect held stable for %s", outageSettleWindow)
	})
}

// redirectIdentityThroughOutageProxy rewrites ztAPI/ztAPIs in the identity file
// at path so they point at addr instead of the real controller, preserving
// each URL's original scheme and path. Mirrors
// controller_retry_storm_test.go's redirectToDeadController.
func redirectIdentityThroughOutageProxy(t *testing.T, path, addr string) {
	t.Helper()
	content := testutil.ReadIdentityFile(t, path)

	redirect := func(raw string) string {
		u, err := url.Parse(raw)
		require.NoError(t, err, "parse identity file URL %q", raw)
		u.Host = addr
		return u.String()
	}

	content.ZtAPI = redirect(content.ZtAPI)
	for i, api := range content.ZtAPIs {
		content.ZtAPIs[i] = redirect(api)
	}

	raw, err := json.Marshal(content)
	require.NoError(t, err, "marshal doctored identity file")
	require.NoError(t, os.WriteFile(path, raw, 0o600), "write doctored identity file %s", path)
}
