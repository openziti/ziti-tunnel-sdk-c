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

var (
	zetBin       string
	zitiBin      string
	dexBin       string
	zetLogDir    string
	zetVerbosity int
	tlsuvDebug   int
	overlay      *testutil.Overlay
	zet          *testutil.ZET
	zetB         *testutil.ZET
	dex          *testutil.Dex
	overlayHome  string
	zetTempRoot  string
)

func TestMain(m *testing.M) {
	flag.StringVar(&zetBin, "zet-bin", "", "path to ziti-edge-tunnel binary (required)")
	flag.StringVar(&zitiBin, "ziti-bin", "", "path to ziti binary for controller+router bring-up (required)")
	flag.StringVar(&dexBin, "dex-bin", "", "path to dex binary (optional; enables tests that need an external IdP)")
	flag.StringVar(&zetLogDir, "zet-log-dir", "", "if set, write each zet's combined stdout+stderr to <dir>/zet-<name>.log")
	flag.IntVar(&zetVerbosity, "zet-verbosity", 4, "ziti-edge-tunnel -v level (0=silent..6=trace)")
	flag.IntVar(&tlsuvDebug, "tlsuv-debug", 0, "TLSUV_DEBUG level (0=off..6=trace); off by default")
	flag.StringVar(&overlayHome, "overlay-home", filepath.Join(os.TempDir(), "ziti-tunnel-test-quickstart"), "directory for the test overlay's persistent quickstart state (PKI lives here across runs)")
	flag.Parse()

	if zetBin == "" || zitiBin == "" {
		fmt.Fprintln(os.Stderr, "both -zet-bin and -ziti-bin are required")
		os.Exit(2)
	}

	code, err := run(m)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(code)
}

func run(m *testing.M) (int, error) {
	if err := testutil.RequireAdmin(); err != nil {
		return 0, err
	}
	if zetLogDir == "" {
		zetLogDir = filepath.Join(overlayHome, "zet-logs")
	}
	var err error
	zetTempRoot, err = os.MkdirTemp("", "ziti-tunnel-zet-*")
	if err != nil {
		return 0, fmt.Errorf("create zet temp root: %w", err)
	}
	log.Printf("setup: zet temp root %s", zetTempRoot)
	defer os.RemoveAll(zetTempRoot)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	log.Printf("setup: starting overlay (zitiBin=%s overlayHome=%s)", zitiBin, overlayHome)
	overlay, err = testutil.StartOverlay(ctx, zitiBin, overlayHome)
	if err != nil {
		return 0, fmt.Errorf("start overlay: %w", err)
	}
	defer overlay.Stop()
	defer func() {
		if cmd := overlay.CACleanupCommand(); cmd != "" {
			log.Printf(`

========================================
teardown: to remove test CA from OS trust when done:

  %s

========================================
`, cmd)
		}
	}()

	log.Printf("setup: purging stale Test* identities")
	if err := overlay.PurgeIdentities(ctx, "Test"); err != nil {
		return 0, fmt.Errorf("purge stale test identities: %w", err)
	}
	log.Printf("setup: purging stale Test* auth-policies")
	if err := overlay.PurgeAuthPolicies(ctx, "Test"); err != nil {
		return 0, fmt.Errorf("purge stale test auth policies: %w", err)
	}
	log.Printf("setup: purging stale Test* ext-jwt-signers")
	if err := overlay.PurgeExtJwtSigners(ctx, "Test"); err != nil {
		return 0, fmt.Errorf("purge stale test ext-jwt-signers: %w", err)
	}

	log.Printf("setup: starting ZET zetA and zetB in parallel")
	var zetAErr, zetBErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		zet, zetAErr = testutil.StartZET(ctx, zetBin, filepath.Join(zetTempRoot, "zet-identities"), testutil.ZETOptions{
			Discriminator: "zetA",
			DNSRange:      "100.129.0.1/16",
			LogDir:        zetLogDir,
			Verbosity:     zetVerbosity,
			TlsuvDebug:    tlsuvDebug,
		})
	}()
	go func() {
		defer wg.Done()
		zetB, zetBErr = testutil.StartZET(ctx, zetBin, filepath.Join(zetTempRoot, "zetB-identities"), testutil.ZETOptions{
			Discriminator: "zetB",
			DNSRange:      "100.128.0.1/16",
			LogDir:        zetLogDir,
			Verbosity:     zetVerbosity,
			TlsuvDebug:    tlsuvDebug,
		})
	}()
	wg.Wait()
	if zet != nil {
		defer zet.Stop()
	}
	if zetB != nil {
		defer zetB.Stop()
	}
	if zetAErr != nil {
		return 0, fmt.Errorf("start ziti-edge-tunnel: %w", zetAErr)
	}
	if zetBErr != nil {
		return 0, fmt.Errorf("start zetB: %w", zetBErr)
	}

	if dexBin != "" {
		log.Printf("setup: starting dex (dexBin=%s)", dexBin)
		dex, err = testutil.StartDex(ctx, dexBin, filepath.Join(zetTempRoot, "dex"))
		if err != nil {
			return 0, fmt.Errorf("start dex: %w", err)
		}
		defer dex.Stop()
	} else {
		log.Printf("setup: -dex-bin not provided; tests that require an external IdP will be skipped")
	}

	log.Printf("setup: running tests")
	return m.Run(), nil
}
