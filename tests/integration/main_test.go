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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openziti/ziti-tunnel-sdk-c/tests/integration/testutil"
)

var (
	zetBin      string
	zitiBin     string
	zetLogDir   string
	overlay     *testutil.Overlay
	zet         *testutil.ZET
	zetB        *testutil.ZET
	overlayHome string
	zetTempRoot string
)

func TestMain(m *testing.M) {
	flag.StringVar(&zetBin, "zet-bin", "", "path to ziti-edge-tunnel binary (required)")
	flag.StringVar(&zitiBin, "ziti-bin", "", "path to ziti binary for controller+router bring-up (required)")
	flag.StringVar(&zetLogDir, "zet-log-dir", "", "if set, write each zet's combined stdout+stderr to <dir>/zet-<name>.log")
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
	if err := testutil.EnsureNoExistingZET(); err != nil {
		return 0, err
	}
	var err error
	zetTempRoot, err = os.MkdirTemp("", "ziti-tunnel-zet-*")
	if err != nil {
		return 0, fmt.Errorf("create zet temp root: %w", err)
	}
	defer os.RemoveAll(zetTempRoot)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	overlay, err = testutil.StartOverlay(ctx, zitiBin, overlayHome)
	if err != nil {
		return 0, fmt.Errorf("start overlay: %w", err)
	}
	defer overlay.Stop()

	if err := overlay.PurgeIdentities(ctx, "Test"); err != nil {
		return 0, fmt.Errorf("purge stale test identities: %w", err)
	}
	if err := overlay.PurgeAuthPolicies(ctx, "Test"); err != nil {
		return 0, fmt.Errorf("purge stale test auth policies: %w", err)
	}
	if err := overlay.PurgeExtJwtSigners(ctx, "Test"); err != nil {
		return 0, fmt.Errorf("purge stale test ext-jwt-signers: %w", err)
	}

	zet, err = testutil.StartZET(ctx, zetBin, filepath.Join(zetTempRoot, "zet-identities"), testutil.ZETOptions{
		LogDir: zetLogDir,
	})
	if err != nil {
		return 0, fmt.Errorf("start ziti-edge-tunnel: %w", err)
	}
	defer zet.Stop()

	zetB, err = testutil.StartZET(ctx, zetBin, filepath.Join(zetTempRoot, "zetB-identities"), testutil.ZETOptions{
		Discriminator: "zetB",
		DNSRange:      "100.128.0.1/10",
		LogDir:        zetLogDir,
	})
	if err != nil {
		return 0, fmt.Errorf("start zetB: %w", err)
	}
	defer zetB.Stop()

	return m.Run(), nil
}
