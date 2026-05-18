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
	// LogDir, if set, causes combined stdout+stderr to be written to
	// <LogDir>/ziti-edge-tunnel[.<discriminator>].log, mirroring the IPC socket
	// naming convention, in addition to the in-memory buffer used by Logs().
	LogDir string
	// Verbosity is the -v level passed to ziti-edge-tunnel (0=silent..6=trace).
	Verbosity int
	// TlsuvDebug, if > 0, sets the TLSUV_DEBUG env var (0=off..6=trace) for
	// debugging TLS handshake / cert chain issues.
	TlsuvDebug int
}

type ZET struct {
	BinPath       string
	CmdPipe       string
	EventPipe     string
	Discriminator string
	LogPath       string

	extCmd  *exec.Cmd
	stdout  *syncBuffer
	stderr  *syncBuffer
	cmdDone chan error
	logFile *os.File
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

	args := []string{"run", "-I", identityDir, "-v", strconv.Itoa(opts.Verbosity)}
	if opts.Discriminator != "" {
		args = append(args, "-P", opts.Discriminator)
	}
	if opts.DNSRange != "" {
		args = append(args, "-d", opts.DNSRange)
	}

	cmd := exec.CommandContext(ctx, binPath, args...)
	if opts.TlsuvDebug > 0 {
		cmd.Env = append(os.Environ(), "TLSUV_DEBUG="+strconv.Itoa(opts.TlsuvDebug))
	}
	stdout := newSyncBuffer()
	stderr := newSyncBuffer()

	var logFile *os.File
	var logPath string
	if opts.LogDir != "" {
		if err := os.MkdirAll(opts.LogDir, 0o755); err != nil {
			return nil, fmt.Errorf("create zet log dir: %w", err)
		}
		logName := "ziti-edge-tunnel"
		if opts.Discriminator != "" {
			logName += "." + opts.Discriminator
		}
		logPath = filepath.Join(opts.LogDir, logName+".log")
		var ferr error
		logFile, ferr = os.OpenFile(logPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
		if ferr != nil {
			return nil, fmt.Errorf("open zet log file: %w", ferr)
		}
		cmd.Stdout = io.MultiWriter(stdout, logFile)
		cmd.Stderr = io.MultiWriter(stderr, logFile)
	} else {
		cmd.Stdout = stdout
		cmd.Stderr = stderr
	}

	log.Printf("zet[%s]: exec %s %s (cmdPipe=%s eventPipe=%s logPath=%s)",
		opts.Discriminator, binPath, strings.Join(args, " "), cmdPipe, eventPipe, logPath)
	if err := cmd.Start(); err != nil {
		if logFile != nil {
			_ = logFile.Close()
		}
		return nil, fmt.Errorf("start %s: %w", binPath, err)
	}
	log.Printf("zet[%s]: process started pid=%d, waiting for IPC pipe", opts.Discriminator, cmd.Process.Pid)

	z := &ZET{
		BinPath:       binPath,
		CmdPipe:       cmdPipe,
		EventPipe:     eventPipe,
		Discriminator: opts.Discriminator,
		LogPath:       logPath,
		extCmd:        cmd,
		stdout:        stdout,
		stderr:        stderr,
		cmdDone:       make(chan error, 1),
		logFile:       logFile,
	}
	go func() { z.cmdDone <- cmd.Wait() }()

	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	client, err := openCommandPipe(dialCtx, cmdPipe)
	if err != nil {
		// Check whether the process already exited before the timeout fired.
		// A non-blocking read from cmdDone disambiguates "process crashed early"
		// from "process is alive but slow to create the socket".
		select {
		case exitErr := <-z.cmdDone:
			return nil, fmt.Errorf("ZET exited (status: %v) before IPC socket appeared\nstdout:\n%s\nstderr:\n%s",
				exitErr, z.stdout.String(), z.stderr.String())
		default:
		}
		z.Stop()
		return nil, fmt.Errorf("waiting for ZET IPC pipe: %w\nstdout:\n%s\nstderr:\n%s",
			err, z.stdout.String(), z.stderr.String())
	}
	client.Close()
	return z, nil
}

// A surviving ZET orphans wintun state and breaks subsequent tests, so abort
// hard rather than let an orphan hide.
func (z *ZET) Stop() {
	if z.extCmd.Process == nil {
		return
	}
	pid := z.extCmd.Process.Pid
	if err := z.extCmd.Process.Kill(); err != nil {
		log.Printf("ZET pid %d kill: %v", pid, err)
	}
	for i := 0; i < 120; i++ {
		time.Sleep(500 * time.Millisecond)
		if proc, err := os.FindProcess(pid); err != nil || proc == nil {
			if z.logFile != nil {
				_ = z.logFile.Close()
			}
			return
		}
		if err := z.extCmd.Process.Signal(syscall.Signal(0)); err != nil {
			if z.logFile != nil {
				_ = z.logFile.Close()
			}
			return
		}
	}
	log.Fatalf("ZET pid %d did not exit within 60s of Kill; orphan likely, aborting test run", pid)
}

func (z *ZET) Logs() string {
	return "zet log: " + z.LogPath
}

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
