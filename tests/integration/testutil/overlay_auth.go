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
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// AuthMode is the authentication mode the controller uses. The sdk
// chooses it from the capabilities the controller advertises, so
// tests state which path they want to test against
type AuthMode string

const (
	AuthOIDC   AuthMode = "OIDC"
	AuthLegacy AuthMode = "Legacy"

	capOidcAuth = "OIDC_AUTH" // the capability whose presence sends clients down the OIDC path.
)

// ApplyAuthMode makes the running controller match o.Auth, then verifies it.
//
// Legacy mode edits the config and restarts: quickstart has no switch for it and always
// generates an OIDC-capable controller. OIDC mode only verifies, since this can remove
// OIDC but not add it.
//
// Call this after the controller has been populated, not from Start. `ziti ops import`
// panics against a controller that does not advertise the OIDC endpoints, so fixtures load
// while OIDC is still up.
func (o *Overlay) ApplyAuthMode() error {
	if o.Auth == AuthLegacy && o.ControllerURL == "" {
		if err := o.restartWithoutOidc(); err != nil {
			return err
		}
	}
	if err := o.verifyAuthMode(); err != nil {
		return err
	}
	o.authApplied = true
	return nil
}

// verifyAuthMode fails unless the advertised capabilities match o.Auth.
func (o *Overlay) verifyAuthMode() error {
	caps, err := o.controllerCapabilities()
	if err != nil {
		return err
	}
	oidc := slices.Contains(caps, capOidcAuth)

	switch o.Auth {
	case AuthOIDC:
		if !oidc {
			return fmt.Errorf("ziti.auth=%s but the controller advertises %v; ziti v%d.%d cannot serve OIDC, or its config disables it",
				AuthOIDC, caps, o.ZitiMajor, o.ZitiMinor)
		}
	case AuthLegacy:
		if oidc {
			hint := "remove the edge-oidc binding and set edge.api.disableOidcAutoBinding: true"
			if o.ControllerURL == "" {
				hint = "the config edit did not take effect"
			}
			return fmt.Errorf("ziti.auth=%s but the controller advertises %v; %s", AuthLegacy, caps, hint)
		}
	default:
		return fmt.Errorf("ziti.auth must be %q or %q, got %q", AuthOIDC, AuthLegacy, o.Auth)
	}
	log.Printf("overlay: auth path verified as %s (capabilities %v)", o.Auth, caps)
	return nil
}

// restartWithoutOidc removes OIDC from the controller config quickstart generated and
// brings the controller back up. Two edits are needed because the versions differ:
// pre-2.0 controllers advertise OIDC only from an explicit edge-oidc web api binding,
// while 2.0+ bind it automatically unless edge.api.disableOidcAutoBinding says otherwise.
func (o *Overlay) restartWithoutOidc() error {
	if err := o.waitForRouterOnline(); err != nil {
		return err
	}

	log.Printf("overlay: removing OIDC from the controller config so clients use the legacy auth path")
	o.Stop()

	paths, err := o.controllerConfigPaths()
	if err != nil {
		return err
	}
	for _, path := range paths {
		if err := disableOidcInConfig(path); err != nil {
			return err
		}
		log.Printf("overlay: OIDC disabled in %s", path)
	}

	if err := o.runQuickstart(); err != nil {
		return fmt.Errorf("restart controller without OIDC: %w", err)
	}
	return nil
}

// EnableOidc reverses disableOidcInConfig, restarts the controller, and flips o.Auth.
// Models an administrator putting OIDC back, the remediation for clients stuck on the
// legacy path.
//
// Callers own the restore: defer RestoreLegacyAuth so later tests see the path the run was
// configured for.
func (o *Overlay) EnableOidc(t *testing.T) {
	require.Equal(t, AuthLegacy, o.Auth, "EnableOidc from auth mode %s", o.Auth)

	log.Printf("overlay: restoring OIDC on the controller")
	o.Stop()

	paths, err := o.controllerConfigPaths()
	require.NoError(t, err, "find controller configs")
	for _, path := range paths {
		require.NoError(t, enableOidcInConfig(path), "restore OIDC in %s", path)
	}

	require.NoError(t, o.runQuickstart(), "restart controller with OIDC")
	o.Auth = AuthOIDC
	require.NoError(t, o.verifyAuthMode(), "controller did not come back advertising OIDC")
}

// RestoreLegacyAuth strips OIDC again after EnableOidc.
func (o *Overlay) RestoreLegacyAuth(t *testing.T) {
	if o.Auth == AuthLegacy {
		return
	}
	o.Auth = AuthLegacy
	require.NoError(t, o.restartWithoutOidc(), "restore legacy auth")
	require.NoError(t, o.verifyAuthMode(), "controller did not come back on the legacy path")
}

// enableOidcInConfig undoes disableOidcInConfig: uncomments the edge-oidc binding and its
// options line, and sets disableOidcAutoBinding back to false. Reversing the edit rather
// than restoring a saved copy keeps this correct on a reused test home, where the config
// was already stripped before the run started.
func enableOidcInConfig(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read controller config %s: %w", path, err)
	}

	var out []string
	restored := false
	uncommentNext := false

	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		bare := strings.TrimSpace(strings.TrimPrefix(trimmed, "#"))

		if strings.HasPrefix(trimmed, "#") && bare == "- binding: edge-oidc" {
			out = append(out, strings.Replace(line, "#", "", 1))
			restored = true
			uncommentNext = true
			continue
		}
		if uncommentNext {
			uncommentNext = false
			if strings.HasPrefix(trimmed, "#") && strings.HasPrefix(bare, "options:") {
				out = append(out, strings.Replace(line, "#", "", 1))
				continue
			}
		}
		if trimmed == "disableOidcAutoBinding: true" {
			out = append(out, strings.Replace(line, "true", "false", 1))
			restored = true
			continue
		}
		out = append(out, line)
	}

	if !restored {
		return fmt.Errorf("no commented edge-oidc binding or disableOidcAutoBinding found in %s", path)
	}
	if err := os.WriteFile(path, []byte(strings.Join(out, "\n")), 0o600); err != nil {
		return fmt.Errorf("write controller config %s: %w", path, err)
	}
	return nil
}

// waitForRouterOnline waits until the quickstart router has enrolled and connected. An
// admin login succeeds before that point. Enrollment writes the router's key and cert,
// which the generated router config points at, so a restart before it fails on the
// missing identity.
func (o *Overlay) waitForRouterOnline() error {
	log.Printf("overlay: waiting for the quickstart router to come online")
	// under doSetup's own 60s guard, so keep this shorter than that: a longer deadline can
	// never elapse and the caller reports "setup did not complete" instead of naming the router
	deadline := time.Now().Add(30 * time.Second)

	for time.Now().Before(deadline) {
		out, err := o.execZiti("edge list edge-routers -j")
		if err == nil {
			var resp struct {
				Data []struct {
					Name     string `json:"name"`
					IsOnline bool   `json:"isOnline"`
				} `json:"data"`
			}
			if jsonErr := json.Unmarshal(out, &resp); jsonErr == nil {
				for _, router := range resp.Data {
					if router.IsOnline {
						log.Printf("overlay: router %q is online", router.Name)
						return nil
					}
				}
			}
		}
		select {
		case err := <-o.Done:
			return fmt.Errorf("quickstart exited before the router came online: %v", err)
		case <-time.After(time.Second):
		}
	}
	return fmt.Errorf("router did not come online within 90s")
}

// controllerConfigPaths returns every generated controller config under o.Home. Single
// node quickstarts before 2.0 write <home>/ctrl.yaml; 2.0+ and cluster mode write one per
// node at <home>/instance-N/ctrl.yaml.
func (o *Overlay) controllerConfigPaths() ([]string, error) {
	var paths []string

	single := filepath.Join(o.Home, "ctrl.yaml")
	if _, err := os.Stat(single); err == nil {
		paths = append(paths, single)
	}

	perInstance, err := filepath.Glob(filepath.Join(o.Home, "instance-*", "ctrl.yaml"))
	if err != nil {
		return nil, fmt.Errorf("glob instance configs under %s: %w", o.Home, err)
	}
	paths = append(paths, perInstance...)

	if len(paths) == 0 {
		return nil, fmt.Errorf("no controller config found under %s", o.Home)
	}
	return paths, nil
}

// disableOidcInConfig comments out the edge-oidc web api binding and sets
// disableOidcAutoBinding under edge.api. Both edits are idempotent, and the
// disableOidcAutoBinding key is ignored by versions that predate it.
func disableOidcInConfig(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read controller config %s: %w", path, err)
	}

	lines := strings.Split(string(raw), "\n")
	// the key is present either way once this has run; only "true" means it is applied
	alreadySet := strings.Contains(string(raw), "disableOidcAutoBinding: true")
	keyPresent := strings.Contains(string(raw), "disableOidcAutoBinding:")

	var out []string
	inEdge := false
	skipNext := false
	commentedBinding := false
	setAutoBinding := false

	for i, line := range lines {
		if skipNext {
			skipNext = false
			continue
		}
		trimmed := strings.TrimSpace(line)

		// EnableOidc leaves the key behind set to false
		if trimmed == "disableOidcAutoBinding: false" {
			out = append(out, strings.Replace(line, "false", "true", 1))
			setAutoBinding = true
			continue
		}

		// comment the binding, and the options line that belongs to it
		if trimmed == "- binding: edge-oidc" {
			indent := line[:len(line)-len(strings.TrimLeft(line, " "))]
			out = append(out, "#"+line)
			if i+1 < len(lines) && strings.HasPrefix(lines[i+1], indent+"  options:") {
				out = append(out, "#"+lines[i+1])
				skipNext = true
			}
			commentedBinding = true
			continue
		}

		out = append(out, line)

		// edge.api is where the 2.0+ auto-binding opt-out lives
		if trimmed == "edge:" && !strings.HasPrefix(line, " ") {
			inEdge = true
			continue
		}
		if inEdge && trimmed == "api:" {
			inEdge = false
			if !keyPresent {
				out = append(out, "    disableOidcAutoBinding: true")
				setAutoBinding = true
			}
		}
	}

	if !commentedBinding && !setAutoBinding && !alreadySet {
		return fmt.Errorf("neither an edge-oidc binding nor an edge.api section found in %s", path)
	}

	if err := os.WriteFile(path, []byte(strings.Join(out, "\n")), 0o600); err != nil {
		return fmt.Errorf("write controller config %s: %w", path, err)
	}
	return nil
}

// controllerCapabilities reads the capabilities the controller advertises on its client
// API version endpoint.
func (o *Overlay) controllerCapabilities() ([]string, error) {
	client := insecureClient(5 * time.Second)
	url := o.ControllerHostPort() + "/edge/client/v1/version"
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("get %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get %s: status %d", url, resp.StatusCode)
	}

	var body struct {
		Data struct {
			Capabilities []string `json:"capabilities"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode %s: %w", url, err)
	}
	return body.Data.Capabilities, nil
}

// RequireLegacyAuth skips the test unless this overlay is running on the legacy auth path.
func (o *Overlay) RequireLegacyAuth(t *testing.T) {
	o.requireAuthApplied(t)
	if o.Auth != AuthLegacy {
		t.Skipf("ziti.auth=%s; this test covers the legacy api-session auth path", o.Auth)
	}
}

// RequireOidcAuth skips the test unless this overlay is running on the OIDC auth path.
func (o *Overlay) RequireOidcAuth(t *testing.T) {
	o.requireAuthApplied(t)
	if o.Auth != AuthOIDC {
		t.Skipf("ziti.auth=%s; this test covers the OIDC auth path", o.Auth)
	}
}

// requireAuthApplied fails rather than skips when setup never applied the auth mode.
func (o *Overlay) requireAuthApplied(t *testing.T) {
	require.True(t, o.authApplied, "setup did not call Overlay.ApplyAuthMode; the controller's auth path was never enforced")
}
