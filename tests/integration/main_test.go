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
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/openziti/ziti-tunnel-sdk-c/tests/integration/testutil"
)

const setupTimeout = 45 * time.Second

var state TestState

type TestState struct {
	overlay   *testutil.Overlay
	zetClient *testutil.ZET
	zetHost   *testutil.ZET
	idp       *testutil.IdP
}

func TestMain(m *testing.M) {
	var zetBin string
	var zetBinB string
	var zetVerbosity int
	var zitiBin string
	var tlsuvDebug int
	var testHome string
	var idpBin string
	flag.StringVar(&zetBin, "zet-bin", "", "path to ziti-edge-tunnel binary (required)")
	flag.StringVar(&zetBinB, "zet-bin-b", "", "path to a second ziti-edge-tunnel binary for zetB; defaults to -zet-bin")
	flag.StringVar(&zitiBin, "ziti-bin", "", "path to ziti binary for controller+router bring-up (required)")
	flag.StringVar(&idpBin, "idp-bin", "", "path to IdP binary (optional; enables tests that need an external IdP)")
	flag.IntVar(&zetVerbosity, "zet-verbosity", 4, "ziti-edge-tunnel -v level (0=silent..6=trace)")
	flag.IntVar(&tlsuvDebug, "tlsuv-debug", 0, "TLSUV_DEBUG level (0=off..6=trace); off by default")
	flag.StringVar(&testHome, "test-home", filepath.Join(os.TempDir(), "ziti-tunnel-test-quickstart"), "directory for the test files, overlay home, logs, etc")
	flag.Parse()

	if zetBin == "" || zitiBin == "" {
		fmt.Fprintln(os.Stderr, "both -zet-bin and -ziti-bin are required")
		os.Exit(2)
	}
	if zetBinB == "" {
		zetBinB = zetBin
	}

	zetLogDir := filepath.Join(testHome, "zets")
	state = TestState{
		overlay: &testutil.Overlay{
			ZitiBin: zitiBin,
			Home:    filepath.Join(testHome, "overlay"),
			Done:    make(chan error, 1),
		},
		zetClient: &testutil.ZET{
			BinPath:       zetBin,
			Discriminator: "zetA",
			DNSRange:      "100.129.0.1/16",
			RootDir:       zetLogDir,
			Verbosity:     zetVerbosity,
			TlsuvDebug:    tlsuvDebug,
		},
		zetHost: &testutil.ZET{
			BinPath:       zetBinB,
			Discriminator: "zetB",
			DNSRange:      "100.128.0.1/16",
			RootDir:       zetLogDir,
			Verbosity:     zetVerbosity,
			TlsuvDebug:    tlsuvDebug,
		},
		idp: &testutil.IdP{
			Bin:     idpBin,
			WorkDir: filepath.Join(testHome, "idp"),
		},
	}

	code, err := run(m, state)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(code)
}

func run(m *testing.M, state TestState) (int, error) {
	if err := testutil.RequireAdmin(); err != nil {
		return 0, err
	}

	defer state.overlay.Stop()
	defer state.zetClient.Stop()
	defer state.zetHost.Stop()
	defer state.idp.Stop()
	defer func() {
		if state.overlay.CATrusted() {
			_, cleanup := state.overlay.OSCAStrings()
			log.Printf(`

========================================
teardown: to remove test CA from OS trust when done:

  %s

========================================
`, cleanup)
		}
	}()

	setupDone := make(chan error, 1)
	go func() {
		setupDone <- doSetup(state)
	}()
	select {
	case err := <-setupDone:
		if err != nil {
			return 0, err
		}
	case <-time.After(setupTimeout):
		return 0, fmt.Errorf("setup did not complete within %s", setupTimeout)
	}

	log.Printf("setup: running tests")
	return m.Run(), nil
}

func doSetup(state TestState) error {
	log.Printf("setup: starting overlay (zitiBin=%s overlayHome=%s)", state.overlay.ZitiBin, state.overlay.Home)
	if err := state.overlay.Start(); err != nil {
		return fmt.Errorf("start overlay: %w", err)
	}

	if err := state.overlay.WaitForClusterLeader(); err != nil {
		return fmt.Errorf("wait for cluster leader: %w", err)
	}

	log.Printf("setup: purging stale Test* identities")
	if err := state.overlay.PurgeIdentities("Test"); err != nil {
		return fmt.Errorf("purge stale test identities: %w", err)
	}
	log.Printf("setup: purging stale Test* auth-policies")
	if err := state.overlay.PurgeAuthPolicies("Test"); err != nil {
		return fmt.Errorf("purge stale test auth policies: %w", err)
	}
	log.Printf("setup: purging stale Test* ext-jwt-signers")
	if err := state.overlay.PurgeExtJwtSigners("Test"); err != nil {
		return fmt.Errorf("purge stale test ext-jwt-signers: %w", err)
	}
	log.Printf("setup: purging stale identities for IdP test user %q", testutil.DefaultIdPUser.Email)
	if err := state.overlay.PurgeIdentityByExternalId(testutil.DefaultIdPUser.Email); err != nil {
		return fmt.Errorf("purge stale IdP test user identities: %w", err)
	}

	log.Printf("setup: starting ZET zetA and zetB in parallel")
	var zetClientErr, zetHostErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		zetClientErr = state.zetClient.Start()
		if zetClientErr != nil {
			log.Printf("zet[%s]: start failed: %v; retrying once", state.zetClient.Discriminator, zetClientErr)
			zetClientErr = state.zetClient.Start()
		}
	}()
	go func() {
		defer wg.Done()
		zetHostErr = state.zetHost.Start()
		if zetHostErr != nil {
			log.Printf("zet[%s]: start failed: %v; retrying once", state.zetHost.Discriminator, zetHostErr)
			zetHostErr = state.zetHost.Start()
		}
	}()
	wg.Wait()
	if zetClientErr != nil {
		return fmt.Errorf("start ziti-edge-tunnel: %w", zetClientErr)
	}
	if zetHostErr != nil {
		return fmt.Errorf("start zetB: %w", zetHostErr)
	}

	if state.idp.Bin != "" {
		log.Printf("setup: starting IdP (idpBin=%s)", state.idp.Bin)
		if err := state.idp.Start(); err != nil {
			return fmt.Errorf("start IdP: %w", err)
		}
	} else {
		log.Printf("setup: -idp-bin not provided; tests that require an external IdP will be skipped")
	}

	return nil
}
