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

const fixturePath = "testdata/fixture.json"

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
	if cfg.Ziti.URL != "" && cfg.IdP.UseTestHarnessIdP {
		fmt.Fprintln(os.Stderr, "config sets ziti.url with useTestHarnessIdP=true, but the harness IdP binds to localhost and an external controller cannot reach it - add a signerName or remove ziti.url")
		os.Exit(2)
	}

	zetLogDir := filepath.Join(cfg.TestHome, "zets")
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
			AutoTrustCA:        cfg.Ziti.AutoTrustCA,
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
			UseTestHarnessIdP: cfg.IdP.UseTestHarnessIdP,
			Bin:               cfg.IdP.Binary,
			WorkDir:           filepath.Join(cfg.TestHome, "idp"),
			IssuerURL:         cfg.IdP.Issuer,
			SignerName:        cfg.IdP.SignerName,
			ClientIDWorks:     cfg.IdP.ClientID,
			ClientIDExtraA:    extraA,
			ClientIDExtraB:    extraB,
			Audience:          cfg.IdP.Audience,
			Scopes:            cfg.IdP.Scopes,
			Password:          cfg.IdP.Password,
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
		if state.overlay.AutoTrustCA {
			log.Printf("teardown: removing test CA from OS trust")
			if err := state.overlay.RemoveCATrust(); err != nil {
				log.Printf("teardown: WARNING: remove test CA from OS trust: %v", err)
			}
			return
		}
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

	log.Printf("setup: purging stale test identities")
	if err := state.overlay.PurgeIdentities(); err != nil {
		return fmt.Errorf("purge stale test identities: %w", err)
	}
	log.Printf("setup: purging stale test auth-policies")
	if err := state.overlay.PurgeAuthPolicies(); err != nil {
		return fmt.Errorf("purge stale test auth policies: %w", err)
	}
	log.Printf("setup: purging stale test ext-jwt-signers")
	if err := state.overlay.PurgeExtJwtSigners(); err != nil {
		return fmt.Errorf("purge stale test ext-jwt-signers: %w", err)
	}
	log.Printf("setup: purging stale auto-provisioned IdP identities")
	if err := state.overlay.PurgeIdentitiesByExternalId("@test.com"); err != nil {
		return fmt.Errorf("purge stale IdP test user identities: %w", err)
	}
	log.Printf("setup: purging stale test service-policies")
	if err := state.overlay.PurgeServicePolicies(); err != nil {
		return fmt.Errorf("purge stale test service policies: %w", err)
	}
	log.Printf("setup: purging stale test services")
	if err := state.overlay.PurgeServices(); err != nil {
		return fmt.Errorf("purge stale test services: %w", err)
	}
	log.Printf("setup: purging stale test configs")
	if err := state.overlay.PurgeConfigs(); err != nil {
		return fmt.Errorf("purge stale test configs: %w", err)
	}

	// Import runs before the CA is installed; trust left over from a crashed run is removed first.
	if state.overlay.AutoTrustCA && state.overlay.CATrusted() {
		log.Printf("setup: removing stale test CA from OS trust before fixture import")
		if err := state.overlay.RemoveCATrust(); err != nil {
			log.Printf("setup: WARNING: remove stale test CA from OS trust: %v", err)
		}
	}

	// TODO: remove this check when ziti 1.6 is no longer part of LTS. The 1.6
	// CLI's import login only populates its TLS RootCAs pool for untrusted
	// servers and never falls back to OS roots, so against an OS-trusted
	// controller every import API call fails with "certificate signed by
	// unknown authority".
	if state.overlay.ZitiMajor < 2 && state.overlay.CATrusted() {
		return fmt.Errorf("ziti v%d.%d ops import fails against an OS-trusted controller; remove the CA from OS trust, or set autoTrustCa: true in your test config and rerun", state.overlay.ZitiMajor, state.overlay.ZitiMinor)
	}

	log.Printf("setup: importing fixture %s", fixturePath)
	if err := state.overlay.ImportFixture(fixturePath); err != nil {
		return fmt.Errorf("import fixture: %w", err)
	}

	if state.overlay.AutoTrustCA {
		log.Printf("setup: installing test CA into OS trust")
		if err := state.overlay.InstallCATrust(); err != nil {
			return fmt.Errorf("install test CA into OS trust: %w", err)
		}
	}

	log.Printf("setup: wiping identity dirs before starting ZET(s)")
	if err := state.zetClient.RemoveJSONIdentities(); err != nil {
		return fmt.Errorf("wipe shared identity dir: %w", err)
	}

	// Multi-tunnel works on every OS when ZET >= 1.17.0
	// Tests against an older ZET start only zetA and skip t2t tests.
	if err := state.zetClient.ProbeVersion(); err != nil {
		return fmt.Errorf("probe zetA version: %w", err)
	}
	if err := state.zetHost.ProbeVersion(); err != nil {
		return fmt.Errorf("probe zetB version: %w", err)
	}
	zets := []*testutil.ZET{state.zetClient}
	if state.zetClient.SupportsMultiTunnel() && state.zetHost.SupportsMultiTunnel() {
		zets = append(zets, state.zetHost)
	} else {
		log.Printf("setup: ZET predates multi-tunnel (zetA=%s zetB=%s, need >= 1.17.0) - starting zetA, t2t tests will skip",
			state.zetClient.Version, state.zetHost.Version)
	}

	log.Printf("setup: starting %d ZET(s)", len(zets))
	errs := make([]error, len(zets))
	var wg sync.WaitGroup
	for i := range zets {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			z := zets[i]
			if err := z.Start(); err != nil {
				log.Printf("zet[%s]: start failed: %v; retrying once", z.Discriminator, err)
				errs[i] = z.Start()
			}
		}(i)
	}
	wg.Wait()
	for i := range zets {
		if errs[i] != nil {
			return fmt.Errorf("start zet[%s]: %w", zets[i].Discriminator, errs[i])
		}
	}

	log.Printf("setup: starting IdP (useTestHarnessIdP=%t bin=%s issuer=%s)", state.idp.UseTestHarnessIdP, state.idp.Bin, state.idp.IssuerURL)
	if err := state.idp.Start(); err != nil {
		return fmt.Errorf("start IdP: %w", err)
	}
	return nil
}
