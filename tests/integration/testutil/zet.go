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
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type ZET struct {
	BinPath string
	// Discriminator, if non-empty, is passed as -P to ziti-edge-tunnel so this
	// instance binds its own IPC pipe (…sock.<disc>) rather than the default.
	// Required when running two ZETs side-by-side on one host.
	Discriminator string
	// DNSRange overrides the default 100.64.0.1/10 TUN/DNS CIDR (-d flag).
	// Set this to a disjoint range (e.g. "100.128.0.1/10") for a second ZET so
	// the two TUN devices intercept different address blocks.
	DNSRange string
	// RootDir, the directory where logs and identities will be output
	RootDir string
	// Verbosity is the -v level passed to ziti-edge-tunnel (0=silent..6=trace).
	Verbosity int
	// TlsuvDebug, if > 0, sets the TLSUV_DEBUG env var (0=off..6=trace) for
	// debugging TLS handshake / cert chain issues.
	TlsuvDebug int
	// Major and Minor are this binary's version, set by ProbeVersion.
	Major int
	Minor int

	cmd     *exec.Cmd
	stdout  *syncBuffer
	stderr  *syncBuffer
	cmdDone chan struct{}
	logFile *os.File

	*CommandsClient
	*EventClient
}

// StartZET spawns ziti-edge-tunnel in "run" mode with identityDir as its -I sandbox.
// Returns once the IPC command pipe is dialable, or an error if ZET dies / the deadline expires.
// Fails fast if something is already bound to this instance's IPC pipe.
func (z *ZET) Start() error {
	cmdPipe := CommandPipePathFor(z.Discriminator)
	eventPipe := EventPipePathFor(z.Discriminator)

	if err := ensureNothingOnPipe(cmdPipe); err != nil {
		return err
	}

	if err := os.MkdirAll(z.RootDir, 0o755); err != nil {
		return fmt.Errorf("mkdir zet root dir: %w", err)
	}
	identityDir := filepath.Join(z.RootDir, "identities")
	if err := os.MkdirAll(identityDir, 0o700); err != nil {
		return fmt.Errorf("mkdir identity dir: %w", err)
	}
	if runtime.GOOS != "windows" {
		// Remove stale unix sockets so ZET can bind. ensureNothingOnPipe above
		// already confirmed nothing is listening, so these removes are safe.
		_ = os.Remove(cmdPipe)
		_ = os.Remove(eventPipe)
	}
	args := []string{"run", "-I", identityDir, "-v", strconv.Itoa(z.Verbosity)}
	if z.Discriminator != "" {
		args = append(args, "-P", z.Discriminator)
	}
	if z.DNSRange != "" {
		args = append(args, "-d", z.DNSRange)
	}

	z.cmd = exec.Command(z.BinPath, args...)
	if z.TlsuvDebug > 0 {
		z.cmd.Env = append(os.Environ(), "TLSUV_DEBUG="+strconv.Itoa(z.TlsuvDebug))
	}
	stdout := newSyncBuffer()
	stderr := newSyncBuffer()

	if err := os.MkdirAll(z.LogPath(), 0o755); err != nil {
		return fmt.Errorf("create zet log dir: %w", err)
	}
	logPath := z.LogFile()
	var ferr error
	logFile, ferr := os.OpenFile(logPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if ferr != nil {
		return fmt.Errorf("open zet log file: %w", ferr)
	}
	z.cmd.Stdout = io.MultiWriter(stdout, logFile)
	z.cmd.Stderr = io.MultiWriter(stderr, logFile)

	log.Printf("zet[%s]: exec %s %s (cmdPipe=%s eventPipe=%s logPath=%s)",
		z.Discriminator, z.BinPath, strings.Join(args, " "), cmdPipe, eventPipe, logPath)
	z.cmdDone = make(chan struct{})
	if err := z.cmd.Start(); err != nil {
		if logFile != nil {
			_ = logFile.Close()
		}
		return fmt.Errorf("start %s: %w", z.BinPath, err)
	}
	log.Printf("zet[%s]: process started pid=%d, waiting for IPC pipe", z.Discriminator, z.cmd.Process.Pid)

	go func() {
		_ = z.cmd.Wait()
		close(z.cmdDone)
	}()

	cmds, err := z.DialIPC()
	if err != nil {
		return fmt.Errorf("zet[%s] command pipe: %w", z.Discriminator, err)
	}
	z.CommandsClient = cmds

	events, err := subscribeToEventPipe(EventPipePathFor(z.Discriminator), z.cmdDone)
	if err != nil {
		return fmt.Errorf("zet[%s] event pipe: %w", z.Discriminator, err)
	}
	z.EventClient = events
	return nil
}

// A surviving ZET orphans wintun state and breaks subsequent tests, so abort rather than let an orphan hide.
func (z *ZET) Stop() {
	if z == nil || z.cmd == nil || z.cmd.Process == nil {
		return
	}
	pid := z.cmd.Process.Pid
	if err := z.cmd.Process.Kill(); err != nil {
		log.Printf("ZET pid %d kill: %v", pid, err)
	}
	for range 120 {
		time.Sleep(500 * time.Millisecond)
		if proc, err := os.FindProcess(pid); err != nil || proc == nil {
			if z.logFile != nil {
				_ = z.logFile.Close()
			}
			return
		}
		if err := z.cmd.Process.Signal(syscall.Signal(0)); err != nil {
			if z.logFile != nil {
				_ = z.logFile.Close()
			}
			return
		}
	}
	log.Fatalf("ZET pid %d did not exit within 60s of Kill; orphan likely, aborting test run", pid)
}

// ProbeVersion runs `ziti-edge-tunnel version` and records the reported version.
func (z *ZET) ProbeVersion() error {
	out, err := exec.Command(z.BinPath, "version").Output()
	if err != nil {
		return fmt.Errorf("run %s version: %w", z.BinPath, err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if v := strings.TrimSpace(line); strings.HasPrefix(v, "v") {
			z.Major, z.Minor, err = parseVersion(v)
			if err != nil {
				return fmt.Errorf("%s version: %w", z.BinPath, err)
			}
			return nil
		}
	}
	return fmt.Errorf("no version line in %q from %s version", string(out), z.BinPath)
}

// SupportsMultiTunnel reports whether this ZET can run beside a second ZET on the same host.
// Multi-tunnel works on every OS when ZET >= 1.17.0. Requires version set by ProbeVersion.
func (z *ZET) SupportsMultiTunnel() bool {
	return z.Major > 1 || (z.Major == 1 && z.Minor >= 17)
}

// Restart stops the process and starts it again against the same identity dir.
// Start no longer wipes identities, so enrolled identities persist across the
// restart. Callers wanting a clean slate wipe before the first Start, not here.
func (z *ZET) Restart() error {
	z.Stop()
	return z.Start()
}

// DialIPC connects to this ZET instance's IPC command pipe.
// Retries until the pipe is dialable or the ZET process exits.
func (z *ZET) DialIPC() (*CommandsClient, error) {
	cmds, err := openCommandPipe(CommandPipePathFor(z.Discriminator), z.cmdDone)
	if err != nil {
		return nil, err
	}
	cmds.LogPath = z.LogPath()
	return cmds, nil
}

// ReconnectEvents closes the event pipe and re-subscribes to the same running
// daemon, replacing z.EventClient. The daemon resends its status snapshot on connect.
func (z *ZET) ReconnectEvents(t *testing.T) {
	path := EventPipePathFor(z.Discriminator)
	log.Printf("ipc: reconnecting event pipe %s", path)
	require.NoError(t, z.EventClient.Close(), "close event pipe")
	events, err := subscribeToEventPipe(path, z.cmdDone)
	require.NoError(t, err, "reconnect event pipe")
	z.EventClient = events
}

// RemoveJSONIdentities deletes every *.json file in the identity dir.
func (z *ZET) RemoveJSONIdentities() error {
	identityDir := filepath.Join(z.RootDir, "identities")
	matches, err := filepath.Glob(filepath.Join(identityDir, "*.json"))
	if err != nil {
		return fmt.Errorf("glob identity dir: %w", err)
	}
	if len(matches) == 0 {
		log.Printf("zet[%s]: no *.json identities to remove from %s", z.Discriminator, identityDir)
		return nil
	}
	log.Printf("zet[%s]: removing %d *.json identity file(s) from %s: %v",
		z.Discriminator, len(matches), identityDir, matches)
	for _, m := range matches {
		if err := os.Remove(m); err != nil {
			return fmt.Errorf("remove %s: %w", m, err)
		}
	}
	return nil
}

func (z *ZET) LogPath() string {
	return filepath.Join(z.RootDir, "logs")
}

func (z *ZET) LogFile() string {
	logName := "ziti-edge-tunnel"
	if z.Discriminator != "" {
		logName += "." + z.Discriminator
	}
	return filepath.Join(z.LogPath(), logName+".log")
}

func ensureNothingOnPipe(path string) error {
	conn, err := dialPlatform(path, 500*time.Millisecond)
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
