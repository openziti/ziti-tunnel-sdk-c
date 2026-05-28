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
	var configPath string
	flag.StringVar(&configPath, "config", "", "path to JSON test config (required)")
	flag.Parse()

	if configPath == "" {
		fmt.Fprintln(os.Stderr, "-config is required")
		os.Exit(2)
	}
	cfg, err := testutil.LoadConfig(configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if cfg.Ziti.Binary == "" || cfg.ZetA.Binary == "" {
		fmt.Fprintln(os.Stderr, "config must set ziti.binary and zetA.binary")
		os.Exit(2)
	}

	zetLogDir := filepath.Join(cfg.TestHome, "zets")
	externalID := cfg.IdP.Sub
	if externalID == "" {
		externalID = cfg.IdP.User.Email
	}
	var extraA, extraB string
	if len(cfg.IdP.ExtraClientIDs) > 0 {
		extraA = cfg.IdP.ExtraClientIDs[0]
	}
	if len(cfg.IdP.ExtraClientIDs) > 1 {
		extraB = cfg.IdP.ExtraClientIDs[1]
	}
	state = TestState{
		overlay: &testutil.Overlay{
			ZitiBin:            cfg.Ziti.Binary,
			Home:               filepath.Join(cfg.TestHome, "overlay"),
			ControllerURL:      cfg.Ziti.URL,
			ControllerUser:     cfg.Ziti.User,
			ControllerPassword: cfg.Ziti.Password,
			Done:               make(chan error, 1),
		},
		zetClient: &testutil.ZET{
			BinPath:       cfg.ZetA.Binary,
			Discriminator: "zetA",
			DNSRange:      "100.129.0.1/16",
			RootDir:       zetLogDir,
			Verbosity:     cfg.ZetA.Verbosity,
			TlsuvDebug:    cfg.ZetA.TlsuvDebug,
		},
		zetHost: &testutil.ZET{
			BinPath:       cfg.ZetB.Binary,
			Discriminator: "zetB",
			DNSRange:      "100.128.0.1/16",
			RootDir:       zetLogDir,
			Verbosity:     cfg.ZetB.Verbosity,
			TlsuvDebug:    cfg.ZetB.TlsuvDebug,
		},
		idp: &testutil.IdP{
			Seed:           cfg.IdP.SeedIdP,
			Bin:            cfg.IdP.Binary,
			WorkDir:        filepath.Join(cfg.TestHome, "idp"),
			IssuerURL:      cfg.IdP.Issuer,
			ClientIDWorks:  cfg.IdP.ClientID,
			ClientIDExtraA: extraA,
			ClientIDExtraB: extraB,
			Audience:       cfg.IdP.Audience,
			Sub:            cfg.IdP.Sub,
			Scopes:         cfg.IdP.Scopes,
			Email:          cfg.IdP.User.Email,
			Password:       cfg.IdP.User.Password,
			Username:       cfg.IdP.User.Username,
			UserID:         cfg.IdP.User.UserID,
			ExternalID:     externalID,
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
			if cleanup == "" {
				return
			}
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
	if state.idp.ExternalID != "" {
		log.Printf("setup: purging stale identities for IdP test user externalId=%q", state.idp.ExternalID)
		if err := state.overlay.PurgeIdentityByExternalId(state.idp.ExternalID); err != nil {
			return fmt.Errorf("purge stale IdP test user identities: %w", err)
		}
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

	log.Printf("setup: starting IdP (seed=%t bin=%s issuer=%s)", state.idp.Seed, state.idp.Bin, state.idp.IssuerURL)
	if err := state.idp.Start(); err != nil {
		return fmt.Errorf("start IdP: %w", err)
	}
	return nil
}
