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

var logLevels = []string{"NONE", "ERROR", "WARN", "INFO", "DEBUG", "VERBOSE", "TRACE"}

func TestSetLogLevel(t *testing.T) {
	t.Run("succeeds", succeeds)
}

func succeeds(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		t.Cleanup(func() {
			restoreResp := state.zetClient.SetLogLevel(t, logLevels[state.zetClient.Verbosity])
			restoreResp.AssertSuccess()
		})

		setLogLevelResp := state.zetClient.SetLogLevel(t, "trace")
		setLogLevelResp.AssertSuccess()
	})
}
