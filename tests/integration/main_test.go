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
	zetBin        string
	zitiBin       string
	keepArtifacts bool
	overlay       *testutil.Overlay
	zet           *testutil.ZET
	tempRoot      string
)

func TestMain(m *testing.M) {
	flag.StringVar(&zetBin, "zet-bin", "", "path to ziti-edge-tunnel binary (required)")
	flag.StringVar(&zitiBin, "ziti-bin", "", "path to ziti binary for controller+router bring-up (required)")
	flag.BoolVar(&keepArtifacts, "keep-artifacts", false, "leave temp dirs on disk after tests finish")
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
	tempRoot, err = os.MkdirTemp("", "ziti-tunnel-integ-*")
	if err != nil {
		return 0, fmt.Errorf("create temp root: %w", err)
	}
	defer func() {
		if !keepArtifacts {
			_ = os.RemoveAll(tempRoot)
		} else {
			fmt.Fprintf(os.Stderr, "artifacts kept at %s\n", tempRoot)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	overlay, err = testutil.StartOverlay(ctx, zitiBin, filepath.Join(tempRoot, "overlay"))
	if err != nil {
		return 0, fmt.Errorf("start overlay: %w", err)
	}
	defer overlay.Stop()

	zet, err = testutil.StartZET(ctx, zetBin, filepath.Join(tempRoot, "zet-identities"))
	if err != nil {
		return 0, fmt.Errorf("start ziti-edge-tunnel: %w", err)
	}
	defer zet.Stop()

	return m.Run(), nil
}
