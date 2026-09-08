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
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// edge.api.sessionTimeout (SetSessionTimeout, overlay_session_timeout.go) only
// governs the legacy api-session path. An OIDC-authenticated identity's actual
// session lifetime is these two settings instead, under edge.oidc - unset by
// default (30m access / 24h refresh, per controller/config/config_edge.go),
// so quickstart's generated config has no line for either to edit in place.

// oidcBlockRE matches the exact 3-line "oidc:" block SetOidcTokenDurations
// inserts, so it can be replaced (call again with new values) or removed
// (RestoreDefaultOidcTokenDurations) idempotently.
var oidcBlockRE = regexp.MustCompile(`(?m)^  oidc:\n    accessTokenDuration: \S+\n    refreshTokenDuration: \S+\n`)

// enrollmentLineRE anchors the insertion point: edge.enrollment is a required
// sibling of edge.api that quickstart always generates, immediately after
// where edge.oidc belongs.
var enrollmentLineRE = regexp.MustCompile(`(?m)^  enrollment:\n`)

// SetOidcTokenDurations sets edge.oidc.accessTokenDuration/refreshTokenDuration
// in the generated controller config(s) and restarts quickstart so it takes
// effect. Quickstart mode only (o.ControllerURL must be empty). refresh must be
// at least 1m longer than access or the controller corrects it back toward the
// default and logs a warning instead of erroring.
//
// This mutates shared overlay state for the rest of the test binary's run:
// callers must defer RestoreDefaultOidcTokenDurations(t) to leave the
// controller in its default state for tests that run afterward.
func (o *Overlay) SetOidcTokenDurations(t *testing.T, access, refresh time.Duration) {
	t.Helper()
	require.Empty(t, o.ControllerURL, "SetOidcTokenDurations requires quickstart mode (ziti.url must be empty)")
	require.GreaterOrEqual(t, refresh, access+time.Minute, "refresh (%s) must be at least 1m longer than access (%s)", refresh, access)

	o.Stop()
	paths, err := o.controllerConfigPaths()
	require.NoError(t, err, "find controller configs")
	for _, path := range paths {
		require.NoError(t, setOidcTokenDurationsInConfig(path, access, refresh), "set oidc token durations in %s", path)
	}
	require.NoError(t, o.runQuickstart(), "restart controller with oidc accessTokenDuration=%s refreshTokenDuration=%s", access, refresh)
	log.Printf("overlay: edge.oidc.accessTokenDuration set to %s, refreshTokenDuration set to %s", access, refresh)
}

// RestoreDefaultOidcTokenDurations removes the edge.oidc block
// SetOidcTokenDurations inserted, restoring the controller's implicit
// defaults (30m access / 24h refresh), and restarts quickstart.
func (o *Overlay) RestoreDefaultOidcTokenDurations(t *testing.T) {
	t.Helper()
	require.Empty(t, o.ControllerURL, "RestoreDefaultOidcTokenDurations requires quickstart mode (ziti.url must be empty)")

	o.Stop()
	paths, err := o.controllerConfigPaths()
	require.NoError(t, err, "find controller configs")
	for _, path := range paths {
		require.NoError(t, removeOidcTokenDurationsFromConfig(path), "remove oidc token durations from %s", path)
	}
	require.NoError(t, o.runQuickstart(), "restart controller with default oidc token durations")
	log.Printf("overlay: edge.oidc token durations restored to default")
}

func setOidcTokenDurationsInConfig(path string, access, refresh time.Duration) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read controller config %s: %w", path, err)
	}
	raw = oidcBlockRE.ReplaceAll(raw, nil)
	block := fmt.Sprintf("  oidc:\n    accessTokenDuration: %s\n    refreshTokenDuration: %s\n", access, refresh)
	if !enrollmentLineRE.Match(raw) {
		return fmt.Errorf("no edge.enrollment line found in %s", path)
	}
	out := enrollmentLineRE.ReplaceAll(raw, []byte(block+"  enrollment:\n"))
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return fmt.Errorf("write controller config %s: %w", path, err)
	}
	return nil
}

func removeOidcTokenDurationsFromConfig(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read controller config %s: %w", path, err)
	}
	out := oidcBlockRE.ReplaceAll(raw, nil)
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return fmt.Errorf("write controller config %s: %w", path, err)
	}
	return nil
}
