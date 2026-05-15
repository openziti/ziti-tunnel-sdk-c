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

//go:build !windows

package testutil

import (
	"context"
	"fmt"
	"net"
	"os"
)

func RequireAdmin() error {
	if os.Geteuid() == 0 {
		return nil
	}
	return fmt.Errorf("integration tests must run as root; rerun under sudo")
}

const CommandPipePath = "/tmp/.ziti/ziti-edge-tunnel.sock"
const EventPipePath = "/tmp/.ziti/ziti-edge-tunnel-event.sock"

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

func dialPlatform(ctx context.Context, path string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", path)
}
