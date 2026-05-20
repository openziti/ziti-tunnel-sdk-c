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

package testutil

import (
	"fmt"
	"net"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

func RequireAdmin() error {
	if windows.GetCurrentProcessToken().IsElevated() {
		return nil
	}
	return fmt.Errorf("integration tests must run elevated on Windows; relaunch as Administrator")
}

const CommandPipePath = `\\.\pipe\ziti-edge-tunnel.sock`
const EventPipePath = `\\.\pipe\ziti-edge-tunnel-event.sock`

func CommandPipePathFor(disc string) string {
	if disc == "" {
		return CommandPipePath
	}
	return CommandPipePath + "." + disc
}

func EventPipePathFor(disc string) string {
	if disc == "" {
		return EventPipePath
	}
	return EventPipePath + "." + disc
}

func dialPlatform(path string, timeout time.Duration) (net.Conn, error) {
	return winio.DialPipe(path, &timeout)
}
