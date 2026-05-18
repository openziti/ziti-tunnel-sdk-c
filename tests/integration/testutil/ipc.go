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
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type Command struct {
	Command string `json:"Command"`
	Data    any    `json:"Data,omitempty"`
}

type Response struct {
	Success bool            `json:"Success"`
	Error   string          `json:"Error,omitempty"`
	Code    int             `json:"Code,omitempty"`
	Data    json.RawMessage `json:"Data,omitempty"`
}

type IPCClient struct {
	conn   net.Conn
	reader *bufio.Reader
}

func dialIPCAt(ctx context.Context, path string) (*IPCClient, error) {
	const retryInterval = 100 * time.Millisecond
	log.Printf("ipc: dialing command pipe %s", path)
	start := time.Now()
	attempts := 0
	var lastErr error
	for {
		attempts++
		conn, err := dialPlatform(ctx, path)
		if err == nil {
			log.Printf("ipc: connected to %s after %d attempt(s) in %s", path, attempts, time.Since(start).Round(time.Millisecond))
			return &IPCClient{conn: conn, reader: bufio.NewReader(conn)}, nil
		}
		lastErr = err
		if attempts == 1 || attempts%20 == 0 {
			log.Printf("ipc: dial %s still failing after %d attempt(s): %v", path, attempts, err)
		}
		select {
		case <-ctx.Done():
			log.Printf("ipc: giving up dial %s after %d attempt(s) in %s: %v (last: %v)", path, attempts, time.Since(start).Round(time.Millisecond), ctx.Err(), lastErr)
			return nil, fmt.Errorf("dial %s: %w (last: %v)", path, ctx.Err(), lastErr)
		case <-time.After(retryInterval):
		}
	}
}

// SendCommand writes the command as one JSON line and reads exactly one JSON-line response.
// The response may arrive only after an async handler completes (e.g. AddIdentity waits
// for enrollment), so callers must supply a generous deadline.
func (c *IPCClient) SendCommand(ctx context.Context, cmd Command) (*Response, error) {
	payload, err := json.Marshal(cmd)
	if err != nil {
		return nil, fmt.Errorf("marshal command: %w", err)
	}
	payload = append(payload, '\n')

	if dl, ok := ctx.Deadline(); ok {
		_ = c.conn.SetDeadline(dl)
		defer c.conn.SetDeadline(time.Time{})
	}
	if _, err := c.conn.Write(payload); err != nil {
		return nil, fmt.Errorf("write command: %w", err)
	}
	line, err := c.reader.ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response %q: %w", string(line), err)
	}
	return &resp, nil
}

func (c *IPCClient) Close() error {
	return c.conn.Close()
}

// DialIPC opens the command pipe on z, asserts no error, and registers a
// Close cleanup on t. Returns the client.
func DialIPC(t *testing.T, ctx context.Context, z *ZET) *IPCClient {
	t.Helper()
	c, err := z.DialIPC(ctx)
	require.NoError(t, err, "dial ZET IPC pipe")
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// DialEvents opens the event pipe on z, asserts no error, and registers a
// Close cleanup on t. Returns the client.
func DialEvents(t *testing.T, ctx context.Context, z *ZET) *EventClient {
	t.Helper()
	c, err := z.DialEvents(ctx)
	require.NoError(t, err, "dial ZET event pipe")
	t.Cleanup(func() { _ = c.Close() })
	return c
}

type EventIdentity struct {
	Identifier       string   `json:"Identifier"`
	Active           bool     `json:"Active"`
	MfaEnabled       bool     `json:"MfaEnabled"`
	MfaNeeded        bool     `json:"MfaNeeded"`
	NeedsExtAuth     bool     `json:"NeedsExtAuth"`
	ExtAuthProviders []string `json:"ExtAuthProviders"`
}

type Event struct {
	Op          string        `json:"Op"`
	Action      string        `json:"Action"`
	Fingerprint string        `json:"Fingerprint"`
	Successful  bool          `json:"Successful"`
	Id          EventIdentity `json:"Id"`
}

// EventClient buffers events read from the ZET event pipe by a background
// goroutine started at dial time. WaitFor scans the buffer + waits for new
// events with a 20s cap.
type EventClient struct {
	conn   net.Conn
	reader *bufio.Reader

	mu      sync.Mutex
	events  []Event
	cursor  int
	notify  []chan struct{}
	readErr error
}

func dialEventsAt(ctx context.Context, path string) (*EventClient, error) {
	const retryInterval = 100 * time.Millisecond
	log.Printf("ipc: dialing event pipe %s", path)
	start := time.Now()
	attempts := 0
	var lastErr error
	for {
		attempts++
		conn, err := dialPlatform(ctx, path)
		if err == nil {
			log.Printf("ipc: connected to event pipe %s after %d attempt(s) in %s", path, attempts, time.Since(start).Round(time.Millisecond))
			ec := &EventClient{conn: conn, reader: bufio.NewReader(conn)}
			go ec.readLoop()
			return ec, nil
		}
		lastErr = err
		if attempts == 1 || attempts%20 == 0 {
			log.Printf("ipc: dial event pipe %s still failing after %d attempt(s): %v", path, attempts, err)
		}
		select {
		case <-ctx.Done():
			log.Printf("ipc: giving up event-pipe dial %s after %d attempt(s) in %s: %v (last: %v)", path, attempts, time.Since(start).Round(time.Millisecond), ctx.Err(), lastErr)
			return nil, fmt.Errorf("dial %s: %w (last: %v)", path, ctx.Err(), lastErr)
		case <-time.After(retryInterval):
		}
	}
}

func (c *EventClient) readLoop() {
	for {
		line, err := c.reader.ReadBytes('\n')
		if err != nil {
			c.mu.Lock()
			c.readErr = err
			for _, ch := range c.notify {
				select {
				case ch <- struct{}{}:
				default:
				}
			}
			c.mu.Unlock()
			return
		}
		var parsed Event
		if jerr := json.Unmarshal(line, &parsed); jerr != nil {
			log.Printf("ipc: event parse failed: %v raw=%s", jerr, line)
			continue
		}
		c.mu.Lock()
		c.events = append(c.events, parsed)
		for _, ch := range c.notify {
			select {
			case ch <- struct{}{}:
			default:
			}
		}
		c.mu.Unlock()
	}
}

// WaitFor blocks until the next event matching op/action/fingerprint arrives
// and advances past it. 20s cap.
func (c *EventClient) WaitFor(t *testing.T, ctx context.Context, op, action, fingerprint string) Event {
	t.Helper()
	waitCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	notify := make(chan struct{}, 1)
	c.mu.Lock()
	c.notify = append(c.notify, notify)
	cursor := c.cursor
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		for i, n := range c.notify {
			if n == notify {
				c.notify = append(c.notify[:i], c.notify[i+1:]...)
				break
			}
		}
		c.mu.Unlock()
	}()

	for {
		c.mu.Lock()
		events := c.events
		readErr := c.readErr
		c.mu.Unlock()
		for ; cursor < len(events); cursor++ {
			e := events[cursor]
			if e.Op == op && e.Action == action && e.Fingerprint == fingerprint {
				c.mu.Lock()
				c.cursor = cursor + 1
				c.mu.Unlock()
				return e
			}
		}
		if readErr != nil {
			require.NoError(t, readErr, "event reader exited waiting for %s:%s/%s after %d events", op, action, fingerprint, cursor)
			return Event{}
		}
		select {
		case <-notify:
		case <-waitCtx.Done():
			require.Failf(t, "event wait timeout", "no %s:%s for %q within 20s; saw %d events: %v", op, action, fingerprint, cursor, events)
			return Event{}
		}
	}
}

func (c *EventClient) Close() error {
	return c.conn.Close()
}

