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
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

type ZET struct {
	BinPath     string
	IdentityDir string

	extCmd  *exec.Cmd
	stdout  *syncBuffer
	stderr  *syncBuffer
	cmdDone chan error
}

// StartZET spawns ziti-edge-tunnel in "run" mode with identityDir as its -I sandbox.
// Returns once the IPC command pipe is dialable, or an error if ZET dies / the deadline expires.
// Fails fast if another ziti-edge-tunnel is already bound to the IPC pipe — the
// tests would otherwise either collide with another daemon or hang.
func StartZET(ctx context.Context, binPath, identityDir string) (*ZET, error) {
	if err := ensureNoExistingZET(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(identityDir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir identity dir: %w", err)
	}
	if runtime.GOOS != "windows" {
		// stale unix socket from a previous crashed ZET prevents bind. Safe to
		// remove now — ensureNoExistingZET already proved nothing is listening.
		_ = os.Remove(CommandPipePath)
		_ = os.Remove(EventPipePath)
	}

	cmd := exec.CommandContext(ctx, binPath, "run", "-I", identityDir)
	stdout := newSyncBuffer()
	stderr := newSyncBuffer()
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", binPath, err)
	}

	z := &ZET{
		BinPath:     binPath,
		IdentityDir: identityDir,
		extCmd:      cmd,
		stdout:      stdout,
		stderr:      stderr,
		cmdDone:     make(chan error, 1),
	}
	go func() { z.cmdDone <- cmd.Wait() }()

	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	client, err := DialIPC(dialCtx)
	if err != nil {
		z.Stop()
		return nil, fmt.Errorf("waiting for ZET IPC pipe: %w\nstdout:\n%s\nstderr:\n%s",
			err, z.stdout.String(), z.stderr.String())
	}
	client.Close()
	return z, nil
}

// Stop terminates ZET. Callers should defer this on every test.
func (z *ZET) Stop() {
	if z.extCmd.Process == nil {
		return
	}
	_ = z.extCmd.Process.Kill()
	select {
	case <-z.cmdDone:
	case <-time.After(5 * time.Second):
	}
}

func (z *ZET) Logs() string {
	return fmt.Sprintf("--- stdout ---\n%s\n--- stderr ---\n%s", z.stdout.String(), z.stderr.String())
}

// IdentityFile returns the expected path of an enrolled identity by filename (no extension).
func (z *ZET) IdentityFile(name string) string {
	return filepath.Join(z.IdentityDir, name+".json")
}

func (z *ZET) IdentityIdentifier(name string) string {
	path := z.IdentityFile(name)
	return path
}

// EnsureNoExistingZET returns an error if something is already listening on the
// ziti-edge-tunnel IPC pipe. A successful dial means another daemon owns the pipe.
func EnsureNoExistingZET() error { return ensureNoExistingZET() }

func ensureNoExistingZET() error {
	probeCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	conn, err := dialPlatform(probeCtx, CommandPipePath)
	if err != nil {
		return nil
	}
	_ = conn.Close()
	return fmt.Errorf("another ziti-edge-tunnel is already running on %s; stop it before running tests",
		CommandPipePath)
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func newSyncBuffer() *syncBuffer { return &syncBuffer{} }

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}
