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
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// GenerateConfig runs `ziti edge quickstart --configure-and-exit` against
// o.Home: quickstart does a full ephemeral setup (PKI, router enrollment)
// and shuts everything down again, leaving only the generated config files -
// nothing left running, nothing left listening. Quickstart mode only
// (o.ControllerURL must be empty); single-node only (no ZitiClusterSize
// support, unneeded by any caller so far).
//
// Pairs with the Preconfigure* methods below: editing a config before the
// very first real Start() means that start comes up already fully
// configured, in particular avoiding a trap discovered the hard way - if
// Overlay.BindCtrlPort is used to put a relay in front of the controller,
// the relay's address has to be in place *before* the first real start,
// because every restart's own admin-login check dials o.ControllerHostPort()
// (the relay), and that fails once the controller's configured address no
// longer matches what a direct dial would have used - there's no "start,
// then fix the address" ordering that works once a relay is involved.
func (o *Overlay) GenerateConfig() error {
	if o.ControllerURL != "" {
		return fmt.Errorf("GenerateConfig requires quickstart mode (ControllerURL must be empty)")
	}
	if err := os.MkdirAll(o.Home, 0o755); err != nil {
		return fmt.Errorf("mkdir home: %w", err)
	}
	args := []string{
		"edge", "quickstart",
		"--home=" + o.Home,
		"--ctrl-address=localhost",
		fmt.Sprintf("--ctrl-port=%d", o.bindCtrlPort()),
		"--router-address=localhost",
		fmt.Sprintf("--router-port=%d", o.rtrPort()),
		"--configure-and-exit",
	}
	log.Printf("overlay: generating config %s %s", o.ZitiBin, strings.Join(args, " "))
	cmd := exec.Command(o.ZitiBin, args...)
	cmd.Env = append(os.Environ(),
		"ZITI_CONFIG_DIR="+filepath.Join(o.Home, "cli-config"),
		"PFXLOG_NO_JSON=true",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("configure-and-exit: %w\n%s", err, out)
	}
	log.Printf("overlay: config generated")
	return nil
}

// PreconfigureDisableOidc strips OIDC from a config produced by
// GenerateConfig, before any process has started - unlike
// ApplyAuthMode/restartWithoutOidc, which assume a live overlay to stop,
// edit, and restart, and wait for the router to be online first (an
// ordering concern that doesn't apply here: GenerateConfig's own ephemeral
// run already finished router enrollment before exiting).
func (o *Overlay) PreconfigureDisableOidc(t *testing.T) {
	t.Helper()
	forEachConfig(t, o, func(path string) error { return disableOidcInConfig(path) })
}

// PreconfigureOidcTokenDurations is SetOidcTokenDurations without the
// stop/restart - for a config produced by GenerateConfig, before any
// process has started.
func (o *Overlay) PreconfigureOidcTokenDurations(t *testing.T, access, refresh time.Duration) {
	t.Helper()
	forEachConfig(t, o, func(path string) error { return setOidcTokenDurationsInConfig(path, access, refresh) })
}

// PreconfigureSessionTimeout is SetSessionTimeout without the stop/restart -
// for a config produced by GenerateConfig, before any process has started.
func (o *Overlay) PreconfigureSessionTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	forEachConfig(t, o, func(path string) error { return setSessionTimeoutInConfig(path, d) })
}

// PreconfigureEdgeApiAddress is SetEdgeApiAddress without the stop/restart -
// for a config produced by GenerateConfig, before any process has started.
func (o *Overlay) PreconfigureEdgeApiAddress(t *testing.T, addr string) {
	t.Helper()
	forEachConfig(t, o, func(path string) error {
		if err := setEdgeApiAddressInConfig(path, addr); err != nil {
			return err
		}
		return setBindPointAddressInConfig(path, addr)
	})
}

// forEachConfig runs edit against every generated controller config path.
func forEachConfig(t *testing.T, o *Overlay, edit func(path string) error) {
	t.Helper()
	paths, err := o.controllerConfigPaths()
	require.NoError(t, err, "find controller configs")
	for _, path := range paths {
		require.NoError(t, edit(path), "edit %s", path)
	}
}
