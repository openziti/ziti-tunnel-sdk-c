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
	"testing"

	"github.com/openziti/ziti-tunnel-sdk-c/tests/integration/testutil"
)

// These cover the rejection paths only. A successful update is exercised by
// TestWindowsUpgrade's UpdateInterfaceConfig, which drives the same command with
// a valid IP on a dedicated instance and asserts the persisted config.
func TestUpdateTunIP(t *testing.T) {
	t.Run("withPrefixAndNoIpRejected", withPrefixAndNoIpRejected)
	t.Run("withEmptyIpRejected", withEmptyIpRejected)
	t.Run("withPrefixTooSmallRejected", withPrefixTooSmallRejected)
	t.Run("withPrefixTooLargeRejected", withPrefixTooLargeRejected)
	t.Run("withMalformedIpRejected", withMalformedIpRejected)
}

func withPrefixAndNoIpRejected(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		resp := state.zetClient.UpdateTunIPv4(t, testutil.TunIPv4Data{TunPrefixLength: 16})
		resp.AssertFail(500, "Tun IP is required")
	})
}

func withEmptyIpRejected(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		ip := ""
		resp := state.zetClient.UpdateTunIPv4(t, testutil.TunIPv4Data{TunIPv4: &ip, TunPrefixLength: 16})
		resp.AssertFail(500, "Invalid IP address")
	})
}

func withPrefixTooSmallRejected(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		ip := "100.64.0.1"
		resp := state.zetClient.UpdateTunIPv4(t, testutil.TunIPv4Data{TunIPv4: &ip, TunPrefixLength: 9})
		resp.AssertFail(500, "prefix length should be between 10 and 18")
	})
}

func withPrefixTooLargeRejected(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		ip := "100.64.0.1"
		resp := state.zetClient.UpdateTunIPv4(t, testutil.TunIPv4Data{TunIPv4: &ip, TunPrefixLength: 25})
		resp.AssertFail(500, "prefix length should be between 10 and 18")
	})
}

func withMalformedIpRejected(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		ip := "not-an-ip"
		resp := state.zetClient.UpdateTunIPv4(t, testutil.TunIPv4Data{TunIPv4: &ip, TunPrefixLength: 16})
		resp.AssertFail(500, "Invalid IP address")
	})
}
