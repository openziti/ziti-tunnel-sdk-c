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

// DefaultEdgeSessionTimeout matches the controller's own default
// (edge.api.sessionTimeout: 30m in quickstart's generated config). Callers
// that shorten it with SetSessionTimeout restore it to this when done.
const DefaultEdgeSessionTimeout = 30 * time.Minute

// sessionTimeoutLineRE matches the "sessionTimeout: <duration>" line quickstart
// generates under edge.api. Anchored on the bare key so it can't match the
// router config's unrelated getSessionTimeout/lookupSessionTimeout keys.
var sessionTimeoutLineRE = regexp.MustCompile(`(?m)^(\s*)sessionTimeout:\s*\S+\s*$`)

// SetSessionTimeout edits edge.api.sessionTimeout in the generated controller
// config(s) and restarts quickstart so it takes effect. Quickstart mode only
// (o.ControllerURL must be empty).
//
// This mutates shared overlay state for the rest of the test binary's run, the
// same way ApplyAuthMode's restartWithoutOidc does: callers must defer
// SetSessionTimeout(t, DefaultEdgeSessionTimeout) to leave the controller in
// its default state for tests that run afterward.
func (o *Overlay) SetSessionTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	require.Empty(t, o.ControllerURL, "SetSessionTimeout requires quickstart mode (ziti.url must be empty)")

	o.Stop()
	paths, err := o.controllerConfigPaths()
	require.NoError(t, err, "find controller configs")
	for _, path := range paths {
		require.NoError(t, setSessionTimeoutInConfig(path, d), "set sessionTimeout in %s", path)
	}
	require.NoError(t, o.runQuickstart(), "restart controller with sessionTimeout=%s", d)
	log.Printf("overlay: edge.api.sessionTimeout set to %s", d)
}

func setSessionTimeoutInConfig(path string, d time.Duration) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read controller config %s: %w", path, err)
	}
	if !sessionTimeoutLineRE.Match(raw) {
		return fmt.Errorf("no edge.api.sessionTimeout line found in %s", path)
	}
	replacement := fmt.Sprintf("${1}sessionTimeout: %s", d)
	out := sessionTimeoutLineRE.ReplaceAll(raw, []byte(replacement))
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return fmt.Errorf("write controller config %s: %w", path, err)
	}
	return nil
}
