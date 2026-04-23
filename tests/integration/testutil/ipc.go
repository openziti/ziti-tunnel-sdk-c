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
	"net"
	"time"
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
	conn net.Conn
	r    *bufio.Reader
}

// DialIPC connects to the ZET command pipe, retrying until ctx expires.
func DialIPC(ctx context.Context) (*IPCClient, error) {
	const retryInterval = 100 * time.Millisecond
	var lastErr error
	for {
		conn, err := dialPlatform(ctx)
		if err == nil {
			return &IPCClient{conn: conn, r: bufio.NewReader(conn)}, nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("dial %s: %w (last: %v)", CommandPipePath, ctx.Err(), lastErr)
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
	line, err := c.r.ReadBytes('\n')
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
