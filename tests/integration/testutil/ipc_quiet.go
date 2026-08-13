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
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// AssertNoMfaEvent fails if an mfa event with this action arrives for this identity
// within the window. The WaitFor helpers assert an event arrived; this asserts none did.
//
// Events already seen before this call are ignored; it watches from here forward.
func (c *EventClient) AssertNoMfaEvent(t *testing.T, action, fingerprint string, within time.Duration) {
	c.mu.Lock()
	cursor := c.cursor
	c.mu.Unlock()

	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		events := c.events
		readErr := c.readErr
		c.mu.Unlock()

		for ; cursor < len(events); cursor++ {
			e := events[cursor]
			if e.op == "mfa" && e.action == action && e.fingerprint == fingerprint {
				require.FailNowf(t, "unexpected mfa event",
					"got mfa:%s for %q within %s; the tunneler should be quiet once a code has been accepted",
					action, fingerprint, within)
			}
		}
		require.NoError(t, readErr, "event reader exited while watching for silence")

		time.Sleep(200 * time.Millisecond)
	}
}
