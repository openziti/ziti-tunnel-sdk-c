//go:build !windows

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
	"os"
	"os/exec"
	"syscall"
	"time"
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

func dialPlatform(path string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	return d.Dial("unix", path)
}

// relayStop sends SIGINT, which `quickstart cluster` handles by shutting its node
// children down cleanly.
func relayStop(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Signal(syscall.SIGINT)
	}
}

// detachSession starts cmd in a new session, so it isn't a member of this
// process's process group and won't receive a signal (e.g. SIGINT/SIGHUP)
// sent to that group - by a Ctrl-C, or a terminal/shell tearing down when the
// parent test process exits.
func detachSession(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
