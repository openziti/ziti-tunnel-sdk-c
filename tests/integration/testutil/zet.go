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
	"runtime"
	"sync"
	"time"
)

// ZETOptions are optional parameters for StartZET.
type ZETOptions struct {
	// Discriminator, if non-empty, is passed as -P to ziti-edge-tunnel so this
	// instance binds its own IPC pipe (…sock.<disc>) rather than the default.
	// Required when running two ZETs side-by-side on one host.
	Discriminator string
	// DNSRange overrides the default 100.64.0.1/10 TUN/DNS CIDR (-d flag).
	// Set this to a disjoint range (e.g. "100.128.0.1/10") for a second ZET so
	// the two TUN devices intercept different address blocks.
	DNSRange string
}

type ZET struct {
	BinPath       string
	CmdPipe       string
	EventPipe     string
	Discriminator string

	extCmd  *exec.Cmd
	stdout  *syncBuffer
	stderr  *syncBuffer
	cmdDone chan error
}

// StartZET spawns ziti-edge-tunnel in "run" mode with identityDir as its -I sandbox.
// Returns once the IPC command pipe is dialable, or an error if ZET dies / the deadline expires.
// Fails fast if something is already bound to this instance's IPC pipe.
func StartZET(ctx context.Context, binPath, identityDir string, opts ZETOptions) (*ZET, error) {
	cmdPipe := CommandPipePathFor(opts.Discriminator)
	eventPipe := EventPipePathFor(opts.Discriminator)

	// Fail fast if something is already bound to this instance's pipe.
	if err := ensureNothingOnPipe(cmdPipe); err != nil {
		return nil, err
	}

	if err := os.MkdirAll(identityDir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir identity dir: %w", err)
	}
	if runtime.GOOS != "windows" {
		// Remove stale unix sockets so ZET can bind. ensureNothingOnPipe above
		// already confirmed nothing is listening, so these removes are safe.
		_ = os.Remove(cmdPipe)
		_ = os.Remove(eventPipe)
	}

	args := []string{"run", "-I", identityDir}
	if opts.Discriminator != "" {
		args = append(args, "-P", opts.Discriminator)
	}
	if opts.DNSRange != "" {
		args = append(args, "-d", opts.DNSRange)
	}

	cmd := exec.CommandContext(ctx, binPath, args...)
	stdout := newSyncBuffer()
	stderr := newSyncBuffer()
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", binPath, err)
	}

	z := &ZET{
		BinPath:       binPath,
		CmdPipe:       cmdPipe,
		EventPipe:     eventPipe,
		Discriminator: opts.Discriminator,
		extCmd:        cmd,
		stdout:        stdout,
		stderr:        stderr,
		cmdDone:       make(chan error, 1),
	}
	go func() { z.cmdDone <- cmd.Wait() }()

	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	client, err := dialIPCAt(dialCtx, cmdPipe)
	if err != nil {
		z.Stop()
		return nil, fmt.Errorf("waiting for ZET IPC pipe: %w\nstdout:\n%s\nstderr:\n%s",
			err, z.stdout.String(), z.stderr.String())
	}
	client.Close()
	return z, nil
}

// DialIPC connects to this ZET instance's IPC command pipe, retrying until ctx expires.
func (z *ZET) DialIPC(ctx context.Context) (*IPCClient, error) {
	return dialIPCAt(ctx, z.CmdPipe)
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

// EnsureNoExistingZET returns an error if something is already listening on the
// default ziti-edge-tunnel IPC pipe. A successful dial means another daemon owns the pipe.
func EnsureNoExistingZET() error { return ensureNothingOnPipe(CommandPipePath) }

func ensureNothingOnPipe(path string) error {
	probeCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	conn, err := dialPlatform(probeCtx, path)
	if err != nil {
		return nil
	}
	_ = conn.Close()
	return fmt.Errorf("another ziti-edge-tunnel is already running on %s; stop it before running tests", path)
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
