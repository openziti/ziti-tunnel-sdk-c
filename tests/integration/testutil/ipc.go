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
	dialRetryInterval  = 10 * time.Millisecond
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
	LogPath string
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

func openCommandPipe(path string, done <-chan struct{}) (*CommandsClient, error) {
	log.Printf("ipc: dialing command pipe %s", path)
	start := time.Now()
	for {
		conn, err := dialPlatform(path, dialAttemptTimeout)
		if err == nil {
			log.Printf("ipc: connected to %s in %s", path, time.Since(start).Round(time.Millisecond))
			return &CommandsClient{
				IPCClient: IPCClient{conn: conn, reader: bufio.NewReader(conn)},
			}, nil
		}
		select {
		case <-done:
			log.Printf("ipc: dial connected %s", path)
			return nil, fmt.Errorf("process exited before %s became dialable: %v", path, err)
		case <-time.After(dialRetryInterval):
		}
	}
}

func subscribeToEventPipe(path string, done <-chan struct{}) (*EventClient, error) {
	log.Printf("ipc: dialing event pipe %s", path)
	start := time.Now()
	for {
		conn, err := dialPlatform(path, dialAttemptTimeout)
		if err == nil {
			log.Printf("ipc: connected to event pipe %s in %s", path, time.Since(start).Round(time.Millisecond))
			ec := &EventClient{
				IPCClient: IPCClient{conn: conn, reader: bufio.NewReader(conn)},
			}
			go ec.readLoop()
			return ec, nil
		}
		select {
		case <-done:
			log.Printf("ipc: dial event pipe connected %s", path)
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
	ev.t = t
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
	ev.t = t
	return ev
}

// WaitForStatusEvent waits for the Op:"status" push the daemon sends to every
// event-pipe client on connect.
func (c *EventClient) WaitForStatusEvent(t *testing.T) TunnelStatusEvent {
	raw := c.waitForEvent(t, "status", "", "")
	var ev TunnelStatusEvent
	require.NoError(t, json.Unmarshal(raw, &ev), "parse TunnelStatusEvent: %s", raw)
	return ev
}

func (c *EventClient) Close() error {
	return c.conn.Close()
}

// ---------------------------------------------------------------------------
// CommandsClient methods: each logs the command, sends a typed Function, and
// asserts the IPC send itself succeeded. Callers assert the response outcome
// since some tests expect failures.
// ---------------------------------------------------------------------------

func (c *CommandsClient) RefreshIdentity(t *testing.T, identifier string) *ServiceResponse {
	f := IdentifierFunction{
		ServiceFunction: NewServiceFunction("RefreshIdentity"),
		Data:            NewIdentifierData(identifier),
	}
	t.Logf("sending RefreshIdentity for %q", identifier)
	resp, err := send[IdentifierFunction, ServiceResponse](&c.IPCClient, f)
	require.NoError(t, err, "failed to send RefreshIdentity\n%s", c.LogPath)
	resp.t = t
	return resp
}

func (c *CommandsClient) RemoveIdentity(t *testing.T, identifier string) *ServiceResponse {
	f := IdentifierFunction{
		ServiceFunction: NewServiceFunction("RemoveIdentity"),
		Data:            NewIdentifierData(identifier),
	}
	t.Logf("sending RemoveIdentity for %q", identifier)
	resp, err := send[IdentifierFunction, ServiceResponse](&c.IPCClient, f)
	require.NoError(t, err, "failed to send RemoveIdentity\n%s", c.LogPath)
	resp.t = t
	return resp
}

func (c *CommandsClient) IdentityOnOff(t *testing.T, identifier string, onOff bool) *ServiceResponse {
	f := IdentityOnOffFunction{
		ServiceFunction: NewServiceFunction("IdentityOnOff"),
		Data:            NewIdentityOnOffData(identifier, onOff),
	}
	t.Logf("sending IdentityOnOff(%t) for %q", onOff, identifier)
	resp, err := send[IdentityOnOffFunction, ServiceResponse](&c.IPCClient, f)
	require.NoError(t, err, "failed to send IdentityOnOff(%t)\n%s", onOff, c.LogPath)
	resp.t = t
	return resp
}

func (c *CommandsClient) SetLogLevel(t *testing.T, level string) *ServiceResponse {
	f := SetLogLevelFunction{
		ServiceFunction: NewServiceFunction("SetLogLevel"),
		Data:            NewSetLogLevelData(level),
	}
	t.Logf("sending SetLogLevel(%q)", level)
	resp, err := send[SetLogLevelFunction, ServiceResponse](&c.IPCClient, f)
	require.NoError(t, err, "failed to send SetLogLevel\n%s", c.LogPath)
	resp.t = t
	return resp
}

func (c *CommandsClient) ZitiDump(t *testing.T, identifier, dumpPath string) *ServiceResponse {
	f := ZitiDumpFunction{
		ServiceFunction: NewServiceFunction("ZitiDump"),
		Data:            NewZitiDumpData(identifier, dumpPath),
	}
	t.Logf("sending ZitiDump for %q", identifier)
	resp, err := send[ZitiDumpFunction, ServiceResponse](&c.IPCClient, f)
	require.NoError(t, err, "failed to send ZitiDump\n%s", c.LogPath)
	resp.t = t
	return resp
}

func (c *CommandsClient) IpDump(t *testing.T, dumpPath string) *ServiceResponse {
	f := IpDumpFunction{
		ServiceFunction: NewServiceFunction("IpDump"),
		Data:            NewIpDumpData(dumpPath),
	}
	t.Logf("sending IpDump to %q", dumpPath)
	resp, err := send[IpDumpFunction, ServiceResponse](&c.IPCClient, f)
	require.NoError(t, err, "failed to send IpDump\n%s", c.LogPath)
	resp.t = t
	return resp
}

func (c *CommandsClient) EnableMFA(t *testing.T, identifier string) *MFAEnrollmentResponse {
	f := IdentifierFunction{
		ServiceFunction: NewServiceFunction("EnableMFA"),
		Data:            NewIdentifierData(identifier),
	}
	t.Logf("sending EnableMFA for %q", identifier)
	resp, err := send[IdentifierFunction, MFAEnrollmentResponse](&c.IPCClient, f)
	require.NoError(t, err, "failed to send EnableMFA\n%s", c.LogPath)
	resp.t = t
	return resp
}

func (c *CommandsClient) SubmitMFA(t *testing.T, identifier, code string) *ServiceResponse {
	f := MFAFunction{
		ServiceFunction: NewServiceFunction("SubmitMFA"),
		Data:            NewMFAData(identifier, code),
	}
	t.Logf("sending SubmitMFA code=%q for %q", code, identifier)
	resp, err := send[MFAFunction, ServiceResponse](&c.IPCClient, f)
	require.NoError(t, err, "failed to send SubmitMFA\n%s", c.LogPath)
	resp.t = t
	return resp
}

func (c *CommandsClient) VerifyMFA(t *testing.T, identifier, code string) *ServiceResponse {
	f := MFAFunction{
		ServiceFunction: NewServiceFunction("VerifyMFA"),
		Data:            NewMFAData(identifier, code),
	}
	t.Logf("sending VerifyMFA code=%q for %q", code, identifier)
	resp, err := send[MFAFunction, ServiceResponse](&c.IPCClient, f)
	require.NoError(t, err, "failed to send VerifyMFA\n%s", c.LogPath)
	resp.t = t
	return resp
}

func (c *CommandsClient) RemoveMFA(t *testing.T, identifier, code string) *ServiceResponse {
	f := MFAFunction{
		ServiceFunction: NewServiceFunction("RemoveMFA"),
		Data:            NewMFAData(identifier, code),
	}
	t.Logf("sending RemoveMFA code=%q for %q", code, identifier)
	resp, err := send[MFAFunction, ServiceResponse](&c.IPCClient, f)
	require.NoError(t, err, "failed to send RemoveMFA\n%s", c.LogPath)
	resp.t = t
	return resp
}

func (c *CommandsClient) GenerateMFACodes(t *testing.T, identifier, code string) *ServiceResponse {
	f := MFAFunction{
		ServiceFunction: NewServiceFunction("GenerateMFACodes"),
		Data:            NewMFAData(identifier, code),
	}
	t.Logf("sending GenerateMFACodes for %q", identifier)
	resp, err := send[MFAFunction, ServiceResponse](&c.IPCClient, f)
	require.NoError(t, err, "failed to send GenerateMFACodes\n%s", c.LogPath)
	resp.t = t
	return resp
}

func (c *CommandsClient) GetMFACodes(t *testing.T, identifier, code string) *ServiceResponse {
	f := MFAFunction{
		ServiceFunction: NewServiceFunction("GetMFACodes"),
		Data:            NewMFAData(identifier, code),
	}
	t.Logf("sending GetMFACodes for %q", identifier)
	resp, err := send[MFAFunction, ServiceResponse](&c.IPCClient, f)
	require.NoError(t, err, "failed to send GetMFACodes\n%s", c.LogPath)
	resp.t = t
	return resp
}

func (c *CommandsClient) UpdateInterfaceConfig(t *testing.T, data InterfaceConfigData) *ServiceResponse {
	f := InterfaceConfigFunction{
		ServiceFunction: NewServiceFunction("UpdateInterfaceConfig"),
		Data:            data,
	}
	t.Logf("sending UpdateInterfaceConfig")
	resp, err := send[InterfaceConfigFunction, ServiceResponse](&c.IPCClient, f)
	require.NoError(t, err, "failed to send UpdateInterfaceConfig\n%s", c.LogPath)
	resp.t = t
	return resp
}

func (c *CommandsClient) ExternalAuth(t *testing.T, identifier, provider string) *ExternalAuthResponse {
	f := ExternalAuthFunction{
		ServiceFunction: NewServiceFunction("ExternalAuth"),
		Data:            NewExternalAuthData(identifier, provider),
	}
	t.Logf("sending ExternalAuth provider=%q for %q", provider, identifier)
	resp, err := send[ExternalAuthFunction, ExternalAuthResponse](&c.IPCClient, f)
	require.NoError(t, err, "failed to send ExternalAuth\n%s", c.LogPath)
	resp.t = t
	return resp
}

func (c *CommandsClient) Status(t *testing.T) *StatusUpdateResponse {
	t.Logf("sending Status")
	resp, err := send[ServiceFunction, StatusUpdateResponse](&c.IPCClient, NewServiceFunction("Status"))
	require.NoError(t, err, "failed to send Status\n%s", c.LogPath)
	resp.t = t
	return resp
}

func (c *CommandsClient) AddIdentity(t *testing.T, data AddIdentityData) *AddIdentityResponse {
	f := AddIdentityFunction{
		ServiceFunction: NewServiceFunction("AddIdentity"),
		Data:            data,
	}
	t.Logf("sending AddIdentity for %q", data.IdentityFilename)
	resp, err := send[AddIdentityFunction, AddIdentityResponse](&c.IPCClient, f)
	require.NoError(t, err, "failed to send AddIdentity\n%s", c.LogPath)
	resp.t = t
	return resp
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// AssertSuccess asserts the daemon accepted the command.
func (r *ServiceResponse) AssertSuccess() {
	require.True(r.t, r.Success(), "IPC command failed: error=%q code=%d", r.Error, r.Code)
}

// AssertFail asserts the daemon rejected the command with code and an Error
// containing message. Pass an empty message when the error text is not asserted.
func (r *ServiceResponse) AssertFail(code int, message string) {
	require.Equal(r.t, code, r.Code)
	require.Contains(r.t, r.Error, message)
}

// AssertSuccess asserts the mfa event reports success.
func (e MfaEvent) AssertSuccess() {
	require.True(e.t, e.Successful, "mfa:%s Successful=%t", e.Action, e.Successful)
}

// AssertMfaAuthenticated asserts MFA enabled and MFA required is false.
func (e IdentityEvent) AssertMfaAuthenticated() {
	require.True(e.t, e.Id.MfaEnabled, "identity:%s MfaEnabled=%t", e.Action, e.Id.MfaEnabled)
	require.False(e.t, e.Id.MfaNeeded, "identity:%s MfaNeeded=%t", e.Action, e.Id.MfaNeeded)
}

// GetExternalAuthURL sends ExternalAuth, asserts Code == 0, and returns the ext-auth URL.
func (c *CommandsClient) GetExternalAuthURL(t *testing.T, identifier, provider string) string {
	extAuthResp := c.ExternalAuth(t, identifier, provider)
	extAuthResp.AssertSuccess()
	require.NotEmpty(t, extAuthResp.Data.URL, "ExternalAuth response has empty URL")
	return extAuthResp.Data.URL
}

// DisableEnableIdentity turns the identity off then back on.
func (c *CommandsClient) DisableEnableIdentity(t *testing.T, identifier string) {
	offResp := c.IdentityOnOff(t, identifier, false)
	offResp.AssertSuccess()
	onResp := c.IdentityOnOff(t, identifier, true)
	onResp.AssertSuccess()
}
