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
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	dialAttemptTimeout = 500 * time.Millisecond
	dialRetryInterval  = 100 * time.Millisecond
)

// IPCClient is one end of a JSON-line IPC socket to the daemon.
type IPCClient struct {
	conn   net.Conn
	reader *bufio.Reader
}

func (c *IPCClient) Close() error {
	return c.conn.Close()
}

// send encodes cmd (INPUT) to a JSON line on the wire and decodes one JSON-line
// response into RESP. Blocks indefinitely on a stuck peer.
func send[INPUT, RESP any](c *IPCClient, cmd INPUT) (*RESP, error) {
	if err := json.NewEncoder(c.conn).Encode(cmd); err != nil {
		return nil, fmt.Errorf("send: %w", err)
	}
	var resp RESP
	if err := json.NewDecoder(c.reader).Decode(&resp); err != nil {
		return nil, fmt.Errorf("recv: %w", err)
	}
	return &resp, nil
}

// CommandsClient sends typed commands and reads typed responses on the command pipe.
type CommandsClient struct {
	IPCClient
}

// bufferedEvent stores the raw JSON line plus the matching keys peeked off it
// so the typed WaitForX methods can match without unmarshaling twice.
type bufferedEvent struct {
	raw         json.RawMessage
	op          string
	action      string
	fingerprint string
}

// EventClient reads events from the event pipe via a background goroutine
// started at dial time. The WaitForX methods scan the buffer + wait for new
// events of the requested Op.
type EventClient struct {
	IPCClient

	mu      sync.Mutex
	events  []bufferedEvent
	cursor  int
	notify  []chan struct{}
	readErr error
}

// OpenCommandPipe opens ZET's command pipe and registers Close as a t.Cleanup.
// Retries until the pipe is dialable or the ZET process exits.
func OpenCommandPipe(t *testing.T, z *ZET) *CommandsClient {
	c, err := openCommandPipe(CommandPipePathFor(z.Discriminator), z.cmdDone)
	require.NoError(t, err, "open command pipe")
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func openCommandPipe(path string, done <-chan struct{}) (*CommandsClient, error) {
	log.Printf("ipc: dialing command pipe %s", path)
	start := time.Now()
	attempts := 0
	for {
		attempts++
		conn, err := dialPlatform(path, dialAttemptTimeout)
		if err == nil {
			log.Printf("ipc: connected to %s after %d attempt(s) in %s", path, attempts, time.Since(start).Round(time.Millisecond))
			return &CommandsClient{
				IPCClient: IPCClient{conn: conn, reader: bufio.NewReader(conn)},
			}, nil
		}
		if attempts == 1 || attempts%20 == 0 {
			log.Printf("ipc: dial %s still failing after %d attempt(s): %v", path, attempts, err)
		}
		select {
		case <-done:
			return nil, fmt.Errorf("process exited before %s became dialable: %v", path, err)
		case <-time.After(dialRetryInterval):
		}
	}
}

func subscribeToEventPipe(path string, done <-chan struct{}) (*EventClient, error) {
	log.Printf("ipc: dialing event pipe %s", path)
	start := time.Now()
	attempts := 0
	for {
		attempts++
		conn, err := dialPlatform(path, dialAttemptTimeout)
		if err == nil {
			log.Printf("ipc: connected to event pipe %s after %d attempt(s) in %s", path, attempts, time.Since(start).Round(time.Millisecond))
			ec := &EventClient{
				IPCClient: IPCClient{conn: conn, reader: bufio.NewReader(conn)},
			}
			go ec.readLoop()
			return ec, nil
		}
		if attempts == 1 || attempts%20 == 0 {
			log.Printf("ipc: dial event pipe %s still failing after %d attempt(s): %v", path, attempts, err)
		}
		select {
		case <-done:
			return nil, fmt.Errorf("process exited before event pipe %s became dialable: %v", path, err)
		case <-time.After(dialRetryInterval):
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
		var header struct {
			Op          string `json:"Op"`
			Action      string `json:"Action"`
			Fingerprint string `json:"Fingerprint"`
		}
		if jerr := json.Unmarshal(line, &header); jerr != nil {
			log.Printf("ipc: event parse failed: %v raw=%s", jerr, line)
			continue
		}
		raw := make(json.RawMessage, len(line))
		copy(raw, line)
		c.mu.Lock()
		c.events = append(c.events, bufferedEvent{
			raw:         raw,
			op:          header.Op,
			action:      header.Action,
			fingerprint: header.Fingerprint,
		})
		for _, ch := range c.notify {
			select {
			case ch <- struct{}{}:
			default:
			}
		}
		c.mu.Unlock()
	}
}

// waitForEvent blocks until the next event matching op/action/fingerprint
// arrives, advances past it, and returns its raw JSON. Blocks indefinitely;
// rely on the per-test timeout if the event never comes.
func (c *EventClient) waitForEvent(t *testing.T, op, action, fingerprint string) json.RawMessage {
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
			if e.op == op && e.action == action && e.fingerprint == fingerprint {
				c.mu.Lock()
				c.cursor = cursor + 1
				c.mu.Unlock()
				return e.raw
			}
		}
		if readErr != nil {
			require.NoError(t, readErr, "event reader exited waiting for %s:%s/%s after %d events", op, action, fingerprint, cursor)
			return nil
		}
		<-notify
	}
}

// WaitForIdentity waits for an Op:"identity" event matching action/fingerprint.
func (c *EventClient) WaitForIdentityEvent(t *testing.T, action, fingerprint string) IdentityEvent {
	raw := c.waitForEvent(t, "identity", action, fingerprint)
	var ev IdentityEvent
	require.NoError(t, json.Unmarshal(raw, &ev), "parse IdentityEvent: %s", raw)
	return ev
}

// WaitForController waits for an Op:"controller" event matching action/fingerprint.
func (c *EventClient) WaitForControllerEvent(t *testing.T, action, fingerprint string) ControllerEvent {
	raw := c.waitForEvent(t, "controller", action, fingerprint)
	var ev ControllerEvent
	require.NoError(t, json.Unmarshal(raw, &ev), "parse ControllerEvent: %s", raw)
	return ev
}

// WaitForMfa waits for an Op:"mfa" event matching action/fingerprint.
func (c *EventClient) WaitForMfaEvent(t *testing.T, action, fingerprint string) MfaEvent {
	raw := c.waitForEvent(t, "mfa", action, fingerprint)
	var ev MfaEvent
	require.NoError(t, json.Unmarshal(raw, &ev), "parse MfaEvent: %s", raw)
	return ev
}

func (c *EventClient) Close() error {
	return c.conn.Close()
}

// DialIPC connects to this ZET instance's IPC command pipe.
// Retries until the pipe is dialable or the ZET process exits.
func (z *ZET) DialIPC() (*CommandsClient, error) {
	return openCommandPipe(CommandPipePathFor(z.Discriminator), z.cmdDone)
}

// ---------------------------------------------------------------------------
// CommandsClient methods — each sends a typed Function and returns a typed
// response (or *ServiceResponse for commands that have no payload back).
// ---------------------------------------------------------------------------

func (c *CommandsClient) RefreshIdentity(identifier string) (*ServiceResponse, error) {
	f := IdentifierFunction{
		ServiceFunction: NewServiceFunction("RefreshIdentity"),
		Data:            NewIdentifierData(identifier),
	}
	return send[IdentifierFunction, ServiceResponse](&c.IPCClient, f)
}

func (c *CommandsClient) RemoveIdentity(identifier string) (*ServiceResponse, error) {
	f := IdentifierFunction{
		ServiceFunction: NewServiceFunction("RemoveIdentity"),
		Data:            NewIdentifierData(identifier),
	}
	return send[IdentifierFunction, ServiceResponse](&c.IPCClient, f)
}

func (c *CommandsClient) IdentityOnOff(identifier string, onOff bool) (*ServiceResponse, error) {
	f := IdentityOnOffFunction{
		ServiceFunction: NewServiceFunction("IdentityOnOff"),
		Data:            NewIdentityOnOffData(identifier, onOff),
	}
	return send[IdentityOnOffFunction, ServiceResponse](&c.IPCClient, f)
}

func (c *CommandsClient) SetLogLevel(level string) (*ServiceResponse, error) {
	f := SetLogLevelFunction{
		ServiceFunction: NewServiceFunction("SetLogLevel"),
		Data:            NewSetLogLevelData(level),
	}
	return send[SetLogLevelFunction, ServiceResponse](&c.IPCClient, f)
}

func (c *CommandsClient) ZitiDump(identifier, dumpPath string) (*ServiceResponse, error) {
	f := ZitiDumpFunction{
		ServiceFunction: NewServiceFunction("ZitiDump"),
		Data:            NewZitiDumpData(identifier, dumpPath),
	}
	return send[ZitiDumpFunction, ServiceResponse](&c.IPCClient, f)
}

func (c *CommandsClient) IpDump(dumpPath string) (*ServiceResponse, error) {
	f := IpDumpFunction{
		ServiceFunction: NewServiceFunction("IpDump"),
		Data:            NewIpDumpData(dumpPath),
	}
	return send[IpDumpFunction, ServiceResponse](&c.IPCClient, f)
}

func (c *CommandsClient) EnableMFA(identifier string) (*MFAEnrollmentResponse, error) {
	f := IdentifierFunction{
		ServiceFunction: NewServiceFunction("EnableMFA"),
		Data:            NewIdentifierData(identifier),
	}
	return send[IdentifierFunction, MFAEnrollmentResponse](&c.IPCClient, f)
}

func (c *CommandsClient) SubmitMFA(identifier, code string) (*ServiceResponse, error) {
	f := MFAFunction{
		ServiceFunction: NewServiceFunction("SubmitMFA"),
		Data:            NewMFAData(identifier, code),
	}
	return send[MFAFunction, ServiceResponse](&c.IPCClient, f)
}

func (c *CommandsClient) VerifyMFA(identifier, code string) (*ServiceResponse, error) {
	f := MFAFunction{
		ServiceFunction: NewServiceFunction("VerifyMFA"),
		Data:            NewMFAData(identifier, code),
	}
	return send[MFAFunction, ServiceResponse](&c.IPCClient, f)
}

func (c *CommandsClient) RemoveMFA(identifier, code string) (*ServiceResponse, error) {
	f := MFAFunction{
		ServiceFunction: NewServiceFunction("RemoveMFA"),
		Data:            NewMFAData(identifier, code),
	}
	return send[MFAFunction, ServiceResponse](&c.IPCClient, f)
}

func (c *CommandsClient) GenerateMFACodes(identifier, code string) (*ServiceResponse, error) {
	f := MFAFunction{
		ServiceFunction: NewServiceFunction("GenerateMFACodes"),
		Data:            NewMFAData(identifier, code),
	}
	return send[MFAFunction, ServiceResponse](&c.IPCClient, f)
}

func (c *CommandsClient) GetMFACodes(identifier, code string) (*ServiceResponse, error) {
	f := MFAFunction{
		ServiceFunction: NewServiceFunction("GetMFACodes"),
		Data:            NewMFAData(identifier, code),
	}
	return send[MFAFunction, ServiceResponse](&c.IPCClient, f)
}

func (c *CommandsClient) UpdateInterfaceConfig(data InterfaceConfigData) (*ServiceResponse, error) {
	f := InterfaceConfigFunction{
		ServiceFunction: NewServiceFunction("UpdateInterfaceConfig"),
		Data:            data,
	}
	return send[InterfaceConfigFunction, ServiceResponse](&c.IPCClient, f)
}

func (c *CommandsClient) ExternalAuth(identifier, provider string) (*ExternalAuthResponse, error) {
	f := ExternalAuthFunction{
		ServiceFunction: NewServiceFunction("ExternalAuth"),
		Data:            NewExternalAuthData(identifier, provider),
	}
	return send[ExternalAuthFunction, ExternalAuthResponse](&c.IPCClient, f)
}

func (c *CommandsClient) Status() (*StatusUpdateResponse, error) {
	return send[ServiceFunction, StatusUpdateResponse](&c.IPCClient, NewServiceFunction("Status"))
}

func (c *CommandsClient) AddIdentity(data AddIdentityData) (*AddIdentityResponse, error) {
	f := AddIdentityFunction{
		ServiceFunction: NewServiceFunction("AddIdentity"),
		Data:            data,
	}
	return send[AddIdentityFunction, AddIdentityResponse](&c.IPCClient, f)
}

// ---------------------------------------------------------------------------
// Test helpers built on top of CommandsClient.
// ---------------------------------------------------------------------------

// AddIdentity sends AddIdentity and returns the typed response. Callers assert
// Code == 0 or non-zero themselves since some tests expect rejection.
func AddIdentity(t *testing.T, client *CommandsClient, data AddIdentityData) *AddIdentityResponse {
	t.Logf("calling AddIdentity for %q", data.IdentityFilename)
	resp, err := client.AddIdentity(data)
	require.NoError(t, err, "AddIdentity IPC send")
	return resp
}

// GetExternalAuthURL sends ExternalAuth, asserts Code == 0, and returns the ext-auth URL.
func (c *CommandsClient) GetExternalAuthURL(t *testing.T, identifier, provider, logPath string) string {
	t.Logf("requesting external auth URL from ZET for provider=%q", provider)
	resp, err := c.ExternalAuth(identifier, provider)
	require.NoError(t, err, "ExternalAuth IPC send")
	require.True(t, resp.Success(), "ExternalAuth should succeed: code=%d error=%q\n%s", resp.Code, resp.Error, logPath)
	require.NotEmpty(t, resp.Data.URL, "ExternalAuth response has empty URL")
	return resp.Data.URL
}

// GetMFAEnrollment sends EnableMFA, asserts Code == 0, and returns the enrollment payload.
func (c *CommandsClient) GetMFAEnrollment(identifier string) (*MFAEnrollment, error) {
	resp, err := c.EnableMFA(identifier)
	if err != nil {
		return nil, fmt.Errorf("enable mfa: %w", err)
	}
	if !resp.Success() {
		return nil, fmt.Errorf("enable mfa failed: %s (code %d)", resp.Error, resp.Code)
	}
	return &resp.Data, nil
}
