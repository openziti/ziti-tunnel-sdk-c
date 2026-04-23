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
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const (
	adminUsername = "admin"
	adminPassword = "admin"
)

type Overlay struct {
	ZitiBin        string
	Home           string
	ControllerPort uint16
	RouterPort     uint16

	extCmd  *exec.Cmd
	stdout  *syncBuffer
	stderr  *syncBuffer
	cmdDone chan error
}

// StartOverlay runs `ziti edge quickstart` with ephemeral ports in a temp home,
// waits for the controller to accept an admin login, and returns a handle.
// Callers must defer Stop().
func StartOverlay(ctx context.Context, zitiBin, home string) (*Overlay, error) {
	ctrlPort, err := findAvailablePort()
	if err != nil {
		return nil, fmt.Errorf("allocate controller port: %w", err)
	}
	rtrPort, err := findAvailablePort()
	if err != nil {
		return nil, fmt.Errorf("allocate router port: %w", err)
	}
	if err := os.MkdirAll(home, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir home: %w", err)
	}

	args := []string{
		"edge", "quickstart",
		"--home=" + home,
		"--ctrl-address=localhost",
		fmt.Sprintf("--ctrl-port=%d", ctrlPort),
		"--router-address=localhost",
		fmt.Sprintf("--router-port=%d", rtrPort),
	}
	cmd := exec.CommandContext(ctx, zitiBin, args...)
	cmd.Env = append(os.Environ(),
		"ZITI_HOME="+home,
		"ZITI_CONFIG_DIR="+filepath.Join(home, "cli-config"),
	)
	stdout := newSyncBuffer()
	stderr := newSyncBuffer()
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start quickstart: %w", err)
	}

	o := &Overlay{
		ZitiBin:        zitiBin,
		Home:           home,
		ControllerPort: ctrlPort,
		RouterPort:     rtrPort,
		extCmd:         cmd,
		stdout:         stdout,
		stderr:         stderr,
		cmdDone:        make(chan error, 1),
	}
	go func() { o.cmdDone <- cmd.Wait() }()

	readyCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if err := o.waitUntilReady(readyCtx); err != nil {
		o.Stop()
		return nil, fmt.Errorf("overlay not ready: %w\n%s", err, o.Logs())
	}
	return o, nil
}

func (o *Overlay) ControllerHostPort() string {
	return fmt.Sprintf("https://localhost:%d", o.ControllerPort)
}

func (o *Overlay) Stop() {
	if o.extCmd.Process == nil {
		return
	}
	_ = o.extCmd.Process.Kill()
	select {
	case <-o.cmdDone:
	case <-time.After(10 * time.Second):
	}
}

func (o *Overlay) Logs() string {
	return fmt.Sprintf("--- ziti stdout ---\n%s\n--- ziti stderr ---\n%s",
		o.stdout.String(), o.stderr.String())
}

// CreateIdentityJWT provisions a new (non-admin) identity and returns its enrollment JWT content.
func (o *Overlay) CreateIdentityJWT(ctx context.Context, name string) (string, error) {
	jwtPath := filepath.Join(o.Home, name+".jwt")
	if _, err := o.runZiti(ctx, "edge", "create", "identity", name, "-o", jwtPath); err != nil {
		return "", fmt.Errorf("create identity %s: %w", name, err)
	}
	content, err := os.ReadFile(jwtPath)
	if err != nil {
		return "", fmt.Errorf("read jwt %s: %w", jwtPath, err)
	}
	return string(bytes.TrimSpace(content)), nil
}

func (o *Overlay) waitUntilReady(ctx context.Context) error {
	var lastErr error
	for {
		if _, err := o.runZiti(ctx, "edge", "login", o.ControllerHostPort(),
			"-u", adminUsername, "-p", adminPassword, "--yes"); err == nil {
			return nil
		} else {
			lastErr = err
		}
		select {
		case err := <-o.cmdDone:
			return fmt.Errorf("quickstart exited before becoming ready: %v", err)
		case <-ctx.Done():
			return fmt.Errorf("%w (last login error: %v)", ctx.Err(), lastErr)
		case <-time.After(1 * time.Second):
		}
	}
}

// runZiti invokes the ziti CLI with ZITI_CONFIG_DIR pointed at the overlay's
// session cache, so logins performed during readiness polling carry through.
func (o *Overlay) runZiti(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, o.ZitiBin, args...)
	cmd.Env = append(os.Environ(),
		"ZITI_HOME="+o.Home,
		"ZITI_CONFIG_DIR="+filepath.Join(o.Home, "cli-config"),
	)
	var stdout, stderr syncBuffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s %v: %w\nstdout: %s\nstderr: %s",
			o.ZitiBin, args, err, stdout.String(), stderr.String())
	}
	return []byte(stdout.String()), nil
}

func findAvailablePort() (uint16, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return uint16(l.Addr().(*net.TCPAddr).Port), nil
}
