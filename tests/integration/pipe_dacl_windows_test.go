//go:build windows

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
	"time"

	"github.com/openziti/ziti-tunnel-sdk-c/tests/integration/testutil"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// set_pipe_dacl touches the instance libuv creates at bind, libuv pre-creates three more at listen, and each
// connect consumes one, so the fifth connect lands on the first instance libuv created after an accept
const pipeInstancesToCheck = 5

func TestPipeDacl(t *testing.T) {
	t.Run("commandPipeHasRestrictedDacl", commandPipeHasRestrictedDacl)
	t.Run("eventPipeHasRestrictedDacl", eventPipeHasRestrictedDacl)
}

func commandPipeHasRestrictedDacl(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		assertPipeDacl(t, testutil.CommandPipePathFor(state.zetClient.Discriminator))
	})
}

func eventPipeHasRestrictedDacl(t *testing.T) {
	testutil.RunWithTimeout(t, func(t *testing.T) {
		assertPipeDacl(t, testutil.EventPipePathFor(state.zetClient.Discriminator))
	})
}

func assertPipeDacl(t *testing.T, pipePath string) {
	pathPtr, err := windows.UTF16PtrFromString(pipePath)
	require.NoError(t, err)
	for instance := 0; instance < pipeInstancesToCheck; instance++ {
		// libuv creates the next listening instance only after ZET's loop accepts the previous connect, so a
		// fast reconnect can find every instance busy, winio.DialPipe retries the same way
		handle, openErr := windows.CreateFile(pathPtr, windows.READ_CONTROL, 0, nil, windows.OPEN_EXISTING, 0, 0)
		for openErr == windows.ERROR_PIPE_BUSY {
			time.Sleep(10 * time.Millisecond)
			handle, openErr = windows.CreateFile(pathPtr, windows.READ_CONTROL, 0, nil, windows.OPEN_EXISTING, 0, 0)
		}
		require.NoError(t, openErr)
		descriptor, infoErr := windows.GetSecurityInfo(handle, windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION)
		_ = windows.CloseHandle(handle)
		require.NoError(t, infoErr)

		sddl := descriptor.String()
		t.Logf("%s instance %d: %s", pipePath, instance, sddl)
		// the descriptor set_pipe_dacl writes, as Windows reads it back: protected (P), interactive users (IU)
		// and services (SU) get read and write minus FILE_CREATE_PIPE_INSTANCE, SYSTEM and Administrators full.
		// No entry for Everyone (WD), which uv_pipe_chmod grants read and write, or Anonymous (AN)
		require.Equal(t, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x12019b;;;IU)(A;;0x12019b;;;SU)", sddl)
	}
}
