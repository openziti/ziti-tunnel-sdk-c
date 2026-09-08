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
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// bindPointAddressRE matches a web.bindPoints entry's "- interface: ..." line
// (a YAML list item, so it carries a "- " prefix) through to its "address:"
// line, which quickstart's generated config puts a few comment lines later,
// not immediately after - the (?:\s*#.*\n)* run absorbs any number of those.
// The interface line and any comments are captured verbatim so they can be
// echoed back unchanged; only address, the advertised value, needs to
// change - interface is what the controller actually binds and must stay on
// the real port.
var bindPointAddressRE = regexp.MustCompile(`(?m)^(\s*-?\s*interface:\s*\S+\n(?:\s*#.*\n)*)(\s*)address:\s*\S+\s*$`)

// SetEdgeApiAddress edits edge.api.address and its matching web.bindPoints
// address in the generated controller config(s), then restarts quickstart so
// it takes effect. Quickstart mode only (o.ControllerURL must be empty).
//
// Both edits are required: the controller validates at startup that
// edge.api.address matches one of its own web.bindPoints address values
// (found by crashing into it - "could not find [edge.api.address] value ...
// as a bind point"), so editing just one panics on the next start. The
// bindPoint's separate "interface" field is left alone - it's what actually
// gets bound, while "address" is only the advertised/validated value - so
// the controller keeps listening on the real port throughout.
//
// edge.api.address is what the controller embeds in enrollment JWTs and
// reports back in its own "/controllers" HA-endpoint-list responses - it is
// entirely separate from o.ctrlPort()/o.ControllerHostPort(), which this
// test harness's own ziti CLI calls always use regardless of this setting.
// Pointing it at a controllable relay (see OutageProxy) is what lets a test
// simulate an outage without a client falling back to a real, always-up
// address it discovered independently: a client that has ever learned the
// real address (e.g. from a "/controllers" response, even a single-node
// quickstart's own self-entry) can fail over to it directly once its
// current connection dies, bypassing the proxy entirely - redirecting only
// the identity file's ztAPI is not sufficient on its own.
//
// This is meant for a dedicated, single-purpose overlay instance (one this
// test starts and tears down itself), not the shared one other tests use:
// unlike SetSessionTimeout/SetOidcTokenDurations, there is no restore-to-default
// counterpart, since a shared overlay should never have its address redirected
// out from under other tests in the first place.
func (o *Overlay) SetEdgeApiAddress(t *testing.T, addr string) {
	t.Helper()
	require.Empty(t, o.ControllerURL, "SetEdgeApiAddress requires quickstart mode (ziti.url must be empty)")

	o.Stop()
	paths, err := o.controllerConfigPaths()
	require.NoError(t, err, "find controller configs")
	for _, path := range paths {
		require.NoError(t, setEdgeApiAddressInConfig(path, addr), "set edge.api.address in %s", path)
		require.NoError(t, setBindPointAddressInConfig(path, addr), "set web.bindPoints address in %s", path)
	}
	require.NoError(t, o.runQuickstart(), "restart controller with edge.api.address=%s", addr)
	log.Printf("overlay: edge.api.address (and matching bindPoint address) set to %s", addr)
}

func setBindPointAddressInConfig(path, addr string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read controller config %s: %w", path, err)
	}
	if !bindPointAddressRE.Match(raw) {
		return fmt.Errorf("no web.bindPoints interface/address pair found in %s", path)
	}
	// group 1 already ends in a newline (the interface line's own, or the last
	// comment line's), so no extra "\n" is needed before group 2.
	replacement := "${1}${2}address: " + addr
	out := bindPointAddressRE.ReplaceAll(raw, []byte(replacement))
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return fmt.Errorf("write controller config %s: %w", path, err)
	}
	return nil
}

// setEdgeApiAddressInConfig replaces the "address:" line inside the edge.api
// block (not any other "address:" line elsewhere in the file, e.g. under
// web.bindPoints) by tracking indentation-based scope, the same style
// overlay_auth.go's disableOidcInConfig uses.
func setEdgeApiAddressInConfig(path, addr string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read controller config %s: %w", path, err)
	}

	lines := strings.Split(string(raw), "\n")
	var out []string
	inEdge, inApi, replaced := false, false, false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if trimmed == "edge:" && !strings.HasPrefix(line, " ") {
			inEdge = true
			out = append(out, line)
			continue
		}
		if inEdge && trimmed == "api:" {
			inApi = true
			out = append(out, line)
			continue
		}
		// edge.api's own keys are indented 4 spaces; a non-blank line indented
		// less than that is a sibling of api: (e.g. oidc:/enrollment:), ending
		// the block.
		if inApi && trimmed != "" && !strings.HasPrefix(line, "    ") {
			inApi = false
		}
		if inApi && strings.HasPrefix(trimmed, "address:") {
			indent := line[:len(line)-len(strings.TrimLeft(line, " "))]
			out = append(out, indent+"address: "+addr)
			replaced = true
			continue
		}
		out = append(out, line)
	}

	if !replaced {
		return fmt.Errorf("no edge.api.address line found in %s", path)
	}
	if err := os.WriteFile(path, []byte(strings.Join(out, "\n")), 0o600); err != nil {
		return fmt.Errorf("write controller config %s: %w", path, err)
	}
	return nil
}
