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

type MFAEnrollment struct {
	Identifier      string   `json:"Identifier"`
	IsVerified      bool     `json:"IsVerified"`
	ProvisioningUrl string   `json:"ProvisioningUrl"`
	RecoveryCodes   []string `json:"RecoveryCodes"`
}

// GetMFAEnrollment sends EnableMFA, asserts success, and unmarshals the enrollment response.
func (c *CommandsClient) GetMFAEnrollment(identifier string) (*MFAEnrollment, error) {
	resp, err := c.EnableMFA(identifier)
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
// exactly one response. SendCommand blocks until the response arrives

func (c *CommandsClient) RefreshIdentity(identifier string) (*Response, error) {
	return c.SendCommand(IPCCommand{Action: "RefreshIdentity", Payload: IdentifierData{Identifier: identifier}})
}

func (c *CommandsClient) RemoveIdentity(identifier string) (*Response, error) {
	return c.SendCommand(IPCCommand{Action: "RemoveIdentity", Payload: IdentifierData{Identifier: identifier}})
}

func (c *CommandsClient) IdentityOnOff(identifier string, onOff bool) (*Response, error) {
	return c.SendCommand(IPCCommand{Action: "IdentityOnOff", Payload: IdentityOnOffData{Identifier: identifier, OnOff: onOff}})
}

func (c *CommandsClient) SetLogLevel(level string) (*Response, error) {
	return c.SendCommand(IPCCommand{Action: "SetLogLevel", Payload: SetLogLevelData{Level: level}})
}

func (c *CommandsClient) ZitiDump(identifier, dumpPath string) (*Response, error) {
	return c.SendCommand(IPCCommand{Action: "ZitiDump", Payload: ZitiDumpData{Identifier: identifier, DumpPath: dumpPath}})
}

func (c *CommandsClient) IpDump(dumpPath string) (*Response, error) {
	return c.SendCommand(IPCCommand{Action: "IpDump", Payload: IpDumpData{DumpPath: dumpPath}})
}

func (c *CommandsClient) EnableMFA(identifier string) (*Response, error) {
	return c.SendCommand(IPCCommand{Action: "EnableMFA", Payload: EnableMFAData{Identifier: identifier}})
}

func (c *CommandsClient) SubmitMFA(identifier, code string) (*Response, error) {
	return c.SendCommand(IPCCommand{Action: "SubmitMFA", Payload: MFAData{Identifier: identifier, Code: code}})
}

func (c *CommandsClient) VerifyMFA(identifier, code string) (*Response, error) {
	return c.SendCommand(IPCCommand{Action: "VerifyMFA", Payload: MFAData{Identifier: identifier, Code: code}})
}

func (c *CommandsClient) RemoveMFA(identifier, code string) (*Response, error) {
	return c.SendCommand(IPCCommand{Action: "RemoveMFA", Payload: MFAData{Identifier: identifier, Code: code}})
}

func (c *CommandsClient) GenerateMFACodes(identifier, code string) (*Response, error) {
	return c.SendCommand(IPCCommand{Action: "GenerateMFACodes", Payload: MFAData{Identifier: identifier, Code: code}})
}

func (c *CommandsClient) GetMFACodes(identifier, code string) (*Response, error) {
	return c.SendCommand(IPCCommand{Action: "GetMFACodes", Payload: MFAData{Identifier: identifier, Code: code}})
}

func (c *CommandsClient) UpdateInterfaceConfig(cfg InterfaceConfigData) (*Response, error) {
	return c.SendCommand(IPCCommand{Action: "UpdateInterfaceConfig", Payload: cfg})
}

func (c *CommandsClient) ExternalAuth(identifier, provider string) (*Response, error) {
	return c.SendCommand(IPCCommand{Action: "ExternalAuth", Payload: ExternalAuthData{Identifier: identifier, Provider: provider}})
}

// ExtAuth is the parsed payload of an ExternalAuth response: the URL the user
// must open to begin the OIDC flow.
type ExtAuth struct {
	Identifier string `json:"identifier"`
	URL        string `json:"url"`
}

// ParseExtAuthURL parses the ext-auth URL from a Response carrying an ExtAuth
// payload. Shared between the ExternalAuth IPC response and the AddIdentity-
// with-EnrollMode response
func ParseExtAuthURL(t *testing.T, resp *Response) string {
	var out ExtAuth
	require.NoError(t, json.Unmarshal(resp.Data, &out), "parse ExtAuth response")
	require.NotEmpty(t, out.URL, "ExtAuth response has empty URL")
	return out.URL
}

// GetExternalAuthURL sends ExternalAuth, asserts Success, and returns the ext-auth URL.
func (c *CommandsClient) GetExternalAuthURL(t *testing.T, identifier, provider, logPath string) string {
	t.Logf("requesting external auth URL from ZET for provider=%q", provider)
	resp, err := c.ExternalAuth(identifier, provider)
	require.NoError(t, err, "ExternalAuth IPC send")
	require.True(t, resp.Success, "ExternalAuth should succeed: code=%d error=%q\n%s", resp.Code, resp.Error, logPath)
	return ParseExtAuthURL(t, resp)
}

func (c *CommandsClient) Status() (*Response, error) {
	return c.SendCommand(IPCCommand{Action: "Status"})
}

func (c *CommandsClient) AddIdentity(data AddIdentityData) (*Response, error) {
	return c.SendCommand(IPCCommand{Action: "AddIdentity", Payload: data})
}

func AddIdentity(t *testing.T, client *CommandsClient, data AddIdentityData) *Response {
	t.Logf("calling AddIdentity for %q", data.IdentityFilename)
	resp, err := client.AddIdentity(data)
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
