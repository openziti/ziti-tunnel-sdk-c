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
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Payload structs below mirror the wire JSON emitted/accepted by ziti-edge-tunnel's
// IPC handlers (defined in lib/ziti-tunnel-cbs/include/ziti/ziti_tunnel_cbs.h).
// JSON tags match the C TUNNEL_* macros exactly; do not rename them without
// changing the handlers first.

type IdentifierData struct {
	Identifier string `json:"Identifier"`
}

type IdentityOnOffData struct {
	OnOff      bool   `json:"OnOff"`
	Identifier string `json:"Identifier"`
}

type SetLogLevelData struct {
	Level string `json:"Level"`
}

type ZitiDumpData struct {
	Identifier string `json:"Identifier"`
	DumpPath   string `json:"DumpPath"`
}

type IpDumpData struct {
	DumpPath string `json:"DumpPath"`
}

// MFAData is used by SubmitMFA, VerifyMFA, RemoveMFA, GenerateMFACodes, GetMFACodes.
type MFAData struct {
	Identifier string `json:"Identifier"`
	Code       string `json:"Code"`
}

// EnableMFAData is distinct from MFAData — EnableMFA takes no auth code.
type EnableMFAData struct {
	Identifier string `json:"Identifier"`
}

type TunIPv4Data struct {
	TunIPv4         string `json:"TunIPv4"`
	TunPrefixLength int    `json:"TunPrefixLength"`
	AddDns          bool   `json:"AddDns"`
}

type L2OptionsData struct {
	Enabled       bool   `json:"Enabled"`
	PcapInterface string `json:"PcapInterface"`
}

type InterfaceConfigData struct {
	L3 TunIPv4Data   `json:"L3"`
	L2 L2OptionsData `json:"L2"`
}

type ExternalAuthData struct {
	Identifier string `json:"Identifier"`
	Provider   string `json:"Provider"`
}

type StatusChangeData struct {
	Woke     bool `json:"Woke"`
	Unlocked bool `json:"Unlocked"`
}

type EnrollMode string

const (
	EnrollModeNone  EnrollMode = "none"
	EnrollModeCert  EnrollMode = "cert"
	EnrollModeToken EnrollMode = "token"
)

type AddIdentityData struct {
	UseKeychain      bool        `json:"UseKeychain"`
	IdentityFilename string      `json:"IdentityFilename"`
	JwtContent       *string     `json:"JwtContent"`
	Key              *string     `json:"Key"`
	Certificate      *string     `json:"Certificate"`
	ControllerURL    *string     `json:"ControllerURL"`
	EnrollMode       *EnrollMode `json:"EnrollMode"`
	Provider         *string     `json:"Provider"`
}

type IdentityInfo struct {
	Name    string `json:"Name"`
	Config  string `json:"Config"`
	Network string `json:"Network"`
	Id      string `json:"Id"`
}

type IdentityListData struct {
	Identities []IdentityInfo `json:"Identities"`
}

type IpInfo struct {
	Ip     string `json:"Ip"`
	Subnet string `json:"Subnet"`
	MTU    int    `json:"MTU"`
	DNS    string `json:"DNS"`
}

type ServiceVersion struct {
	Version   string `json:"Version"`
	BuildDate string `json:"BuildDate"`
}

type TapInfo struct{}

type IdentityStatus struct {
	Name             string   `json:"Name"`
	Identifier       string   `json:"Identifier"`
	Active           bool     `json:"Active"`
	FingerPrint      string   `json:"FingerPrint"`
	MfaEnabled       bool     `json:"MfaEnabled"`
	MfaNeeded        bool     `json:"MfaNeeded"`
	NeedsExtAuth     bool     `json:"NeedsExtAuth"`
	ExtAuthProviders []string `json:"ExtAuthProviders"`
}

type TunnelStatus struct {
	Active         bool             `json:"Active"`
	Duration       int64            `json:"Duration"`
	StartTime      string           `json:"StartTime"`
	Identities     []IdentityStatus `json:"Identities"`
	IpInfo         IpInfo           `json:"IpInfo"`
	LogLevel       string           `json:"LogLevel"`
	ServiceVersion ServiceVersion   `json:"ServiceVersion"`
	TunIpv4        string           `json:"TunIpv4"`
	TunIpv4Mask    int              `json:"TunIpv4Mask"`
	AddDns         bool             `json:"AddDns"`
	ApiPageSize    int              `json:"ApiPageSize"`
	TunName        string           `json:"TunName"`
	L2Enabled      bool             `json:"L2Enabled"`
	TapInfo        TapInfo          `json:"TapInfo"`
	ConfigDir      string           `json:"ConfigDir"`
}

// FindIdentity returns the identity entry whose FingerPrint matches, or nil.
// FingerPrint carries the controller-side identity name; Name is mutable and
// gets rewritten to the identity-file path after /current-identity is fetched.
func (s *TunnelStatus) FindIdentity(fingerprint string) *IdentityStatus {
	for i := range s.Identities {
		if s.Identities[i].FingerPrint == fingerprint {
			return &s.Identities[i]
		}
	}
	return nil
}

// GetTunnelStatus sends the Status command, asserts success, and unmarshals the response.
func (c *CommandsClient) GetTunnelStatus(ctx context.Context) (*TunnelStatus, error) {
	resp, err := c.Status(ctx)
	if err != nil {
		return nil, fmt.Errorf("status: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("status failed: %s (code %d)", resp.Error, resp.Code)
	}
	var status TunnelStatus
	if err := json.Unmarshal(resp.Data, &status); err != nil {
		return nil, fmt.Errorf("parse status: %w", err)
	}
	return &status, nil
}

type MFAEnrollment struct {
	Identifier      string   `json:"Identifier"`
	IsVerified      bool     `json:"IsVerified"`
	ProvisioningUrl string   `json:"ProvisioningUrl"`
	RecoveryCodes   []string `json:"RecoveryCodes"`
}

// GetMFAEnrollment sends EnableMFA, asserts success, and unmarshals the enrollment response.
func (c *CommandsClient) GetMFAEnrollment(ctx context.Context, identifier string) (*MFAEnrollment, error) {
	resp, err := c.EnableMFA(ctx, identifier)
	if err != nil {
		return nil, fmt.Errorf("enable mfa: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("enable mfa failed: %s (code %d)", resp.Error, resp.Code)
	}
	var enrollment MFAEnrollment
	if err := json.Unmarshal(resp.Data, &enrollment); err != nil {
		return nil, fmt.Errorf("parse enable mfa response: %w", err)
	}
	return &enrollment, nil
}

// Helper methods send a named command with the appropriate payload and read
// exactly one response. All inherit the context's deadline (used for async
// handlers like AddIdentity that respond only after enrollment completes).

func (c *CommandsClient) RefreshIdentity(ctx context.Context, identifier string) (*Response, error) {
	return c.SendCommand(ctx, IPCCommand{Action: "RefreshIdentity", Payload: IdentifierData{Identifier: identifier}})
}

func (c *CommandsClient) RemoveIdentity(ctx context.Context, identifier string) (*Response, error) {
	return c.SendCommand(ctx, IPCCommand{Action: "RemoveIdentity", Payload: IdentifierData{Identifier: identifier}})
}

func (c *CommandsClient) IdentityOnOff(ctx context.Context, identifier string, onOff bool) (*Response, error) {
	return c.SendCommand(ctx, IPCCommand{Action: "IdentityOnOff", Payload: IdentityOnOffData{Identifier: identifier, OnOff: onOff}})
}

func (c *CommandsClient) SetLogLevel(ctx context.Context, level string) (*Response, error) {
	return c.SendCommand(ctx, IPCCommand{Action: "SetLogLevel", Payload: SetLogLevelData{Level: level}})
}

func (c *CommandsClient) ZitiDump(ctx context.Context, identifier, dumpPath string) (*Response, error) {
	return c.SendCommand(ctx, IPCCommand{Action: "ZitiDump", Payload: ZitiDumpData{Identifier: identifier, DumpPath: dumpPath}})
}

func (c *CommandsClient) IpDump(ctx context.Context, dumpPath string) (*Response, error) {
	return c.SendCommand(ctx, IPCCommand{Action: "IpDump", Payload: IpDumpData{DumpPath: dumpPath}})
}

func (c *CommandsClient) EnableMFA(ctx context.Context, identifier string) (*Response, error) {
	return c.SendCommand(ctx, IPCCommand{Action: "EnableMFA", Payload: EnableMFAData{Identifier: identifier}})
}

func (c *CommandsClient) SubmitMFA(ctx context.Context, identifier, code string) (*Response, error) {
	return c.SendCommand(ctx, IPCCommand{Action: "SubmitMFA", Payload: MFAData{Identifier: identifier, Code: code}})
}

func (c *CommandsClient) VerifyMFA(ctx context.Context, identifier, code string) (*Response, error) {
	return c.SendCommand(ctx, IPCCommand{Action: "VerifyMFA", Payload: MFAData{Identifier: identifier, Code: code}})
}

func (c *CommandsClient) RemoveMFA(ctx context.Context, identifier, code string) (*Response, error) {
	return c.SendCommand(ctx, IPCCommand{Action: "RemoveMFA", Payload: MFAData{Identifier: identifier, Code: code}})
}

func (c *CommandsClient) GenerateMFACodes(ctx context.Context, identifier, code string) (*Response, error) {
	return c.SendCommand(ctx, IPCCommand{Action: "GenerateMFACodes", Payload: MFAData{Identifier: identifier, Code: code}})
}

func (c *CommandsClient) GetMFACodes(ctx context.Context, identifier, code string) (*Response, error) {
	return c.SendCommand(ctx, IPCCommand{Action: "GetMFACodes", Payload: MFAData{Identifier: identifier, Code: code}})
}

func (c *CommandsClient) UpdateInterfaceConfig(ctx context.Context, cfg InterfaceConfigData) (*Response, error) {
	return c.SendCommand(ctx, IPCCommand{Action: "UpdateInterfaceConfig", Payload: cfg})
}

func (c *CommandsClient) ExternalAuth(ctx context.Context, identifier, provider string) (*Response, error) {
	return c.SendCommand(ctx, IPCCommand{Action: "ExternalAuth", Payload: ExternalAuthData{Identifier: identifier, Provider: provider}})
}

// ExtAuth is the parsed payload of an ExternalAuth response: the URL the user
// must open to begin the OIDC flow.
type ExtAuth struct {
	Identifier string `json:"identifier"`
	URL        string `json:"url"`
}

// GetExternalAuthURL sends ExternalAuth, asserts success, parses the response,
// and returns the auth URL. Fails the test on transport error, non-success
// response, parse error, or empty URL.
func (c *CommandsClient) GetExternalAuthURL(t *testing.T, ctx context.Context, identifier, provider string) string {
	t.Logf("requesting external auth URL from ZET for provider=%q", provider)
	resp, err := c.ExternalAuth(ctx, identifier, provider)
	require.NoError(t, err, "ExternalAuth IPC send")
	require.True(t, resp.Success, "ExternalAuth failed: code=%d error=%q", resp.Code, resp.Error)
	var out ExtAuth
	require.NoError(t, json.Unmarshal(resp.Data, &out), "parse ExternalAuth response")
	require.NotEmpty(t, out.URL, "ExternalAuth returned an empty auth URL")
	return out.URL
}

func (c *CommandsClient) Status(ctx context.Context) (*Response, error) {
	return c.SendCommand(ctx, IPCCommand{Action: "Status"})
}

func (c *CommandsClient) ListIdentities(ctx context.Context) (*Response, error) {
	return c.SendCommand(ctx, IPCCommand{Action: "ListIdentities"})
}

func (c *CommandsClient) GetMetrics(ctx context.Context) (*Response, error) {
	return c.SendCommand(ctx, IPCCommand{Action: "GetMetrics"})
}

func (c *CommandsClient) AddIdentity(ctx context.Context, data AddIdentityData) (*Response, error) {
	return c.SendCommand(ctx, IPCCommand{Action: "AddIdentity", Payload: data})
}

func AddIdentity(t *testing.T, ctx context.Context, client *CommandsClient, data AddIdentityData) *Response {
	t.Logf("calling AddIdentity for %q", data.IdentityFilename)
	resp, err := client.AddIdentity(ctx, data)
	require.NoError(t, err, "AddIdentity IPC send")
	return resp
}

// IdentityName returns a filesystem-safe identity filename derived from
// t.Name(). Subtests produce names like "TestX/sub"; ZET rejects the slash
// in AddIdentity filenames, so it is replaced.
func IdentityName(t *testing.T) string {
	return strings.ReplaceAll(t.Name(), "/", "-")
}

type IdentityFileContent struct {
	ZtAPI  string   `json:"ztAPI"`
	ZtAPIs []string `json:"ztAPIs"`
	ID     struct {
		Cert string `json:"cert"`
		Key  string `json:"key"`
		CA   string `json:"ca"`
	} `json:"id"`
}

func ReadIdentityFile(t *testing.T, path string) IdentityFileContent {
	raw, err := os.ReadFile(path)
	require.NoError(t, err, "failed to read identity file at %s", path)

	var content IdentityFileContent
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	require.NoError(t, dec.Decode(&content), "identity file at %s has unknown fields or invalid shape: %s", path, raw)
	return content
}

func AssertValidJwtEnrolledIdentityFile(t *testing.T, path string) {
	content := ReadIdentityFile(t, path)
	require.NotEmpty(t, content.ZtAPI, "identity file ztAPI empty")
	require.NotEmpty(t, content.ID.Cert, "identity file id.cert empty")
	require.NotEmpty(t, content.ID.Key, "identity file id.key empty")
	require.NotEmpty(t, content.ID.CA, "identity file id.ca empty")
}

func AssertValidUrlEnrolledIdentityFile(t *testing.T, path string, mode EnrollMode) {
	content := ReadIdentityFile(t, path)
	require.NotEmpty(t, content.ZtAPI, "identity file ztAPI empty")
	require.NotEmpty(t, content.ID.CA, "identity file id.ca empty")
	switch mode {
	case EnrollModeNone:
		require.Empty(t, content.ID.Cert, "identity file id.cert should be empty for URL enroll-to-none")
		require.Empty(t, content.ID.Key, "identity file id.key should be empty for URL enroll-to-none")
	case EnrollModeCert, EnrollModeToken:
		require.NotEmpty(t, content.ID.Cert, "identity file id.cert empty")
		require.NotEmpty(t, content.ID.Key, "identity file id.key empty")
	}
}
