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
	"context"
	"encoding/json"
)

// Payload structs below mirror the wire JSON emitted/accepted by ziti-edge-tunnel's
// IPC handlers (defined in lib/ziti-tunnel-cbs/include/ziti/ziti_tunnel_cbs.h).
// JSON tags match the C TUNNEL_* macros exactly; do not rename them without
// changing the handlers first.

type IdentifierData struct {
	Identifier string `json:"Identifier"`
}

type IdentityOnOffData struct {
	Identifier string `json:"Identifier"`
	OnOff      bool   `json:"OnOff"`
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

type AddIdentityData struct {
	IdentityFilename string `json:"IdentityFilename"`
	JwtContent       string `json:"JwtContent,omitempty"`
	Certificate      string `json:"Certificate,omitempty"`
	Key              string `json:"Key,omitempty"`
	ControllerURL    string `json:"ControllerURL,omitempty"`
	EnrollMode       string `json:"EnrollMode,omitempty"`
	Provider         string `json:"Provider,omitempty"`
	UseKeychain      bool   `json:"UseKeychain,omitempty"`
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

type TunnelStatus struct {
	Active         bool            `json:"Active"`
	Duration       int64           `json:"Duration"`
	StartTime      string          `json:"StartTime"`
	Identities     json.RawMessage `json:"Identities"`
	IpInfo         IpInfo          `json:"IpInfo"`
	LogLevel       string          `json:"LogLevel"`
	ServiceVersion ServiceVersion  `json:"ServiceVersion"`
	TunIpv4        string          `json:"TunIpv4"`
	TunIpv4Mask    int             `json:"TunIpv4Mask"`
	AddDns         bool            `json:"AddDns"`
	ApiPageSize    int             `json:"ApiPageSize"`
	TunName        string          `json:"TunName"`
	L2Enabled      bool            `json:"L2Enabled"`
	TapInfo        TapInfo         `json:"TapInfo"`
}

// Helper methods send a named command with the appropriate payload and read
// exactly one response. All inherit the context's deadline (used for async
// handlers like AddIdentity that respond only after enrollment completes).

func (c *IPCClient) RefreshIdentity(ctx context.Context, identifier string) (*Response, error) {
	return c.SendCommand(ctx, Command{Command: "RefreshIdentity", Data: IdentifierData{Identifier: identifier}})
}

func (c *IPCClient) RemoveIdentity(ctx context.Context, identifier string) (*Response, error) {
	return c.SendCommand(ctx, Command{Command: "RemoveIdentity", Data: IdentifierData{Identifier: identifier}})
}

func (c *IPCClient) IdentityOnOff(ctx context.Context, identifier string, onOff bool) (*Response, error) {
	return c.SendCommand(ctx, Command{Command: "IdentityOnOff", Data: IdentityOnOffData{Identifier: identifier, OnOff: onOff}})
}

func (c *IPCClient) SetLogLevel(ctx context.Context, level string) (*Response, error) {
	return c.SendCommand(ctx, Command{Command: "SetLogLevel", Data: SetLogLevelData{Level: level}})
}

func (c *IPCClient) ZitiDump(ctx context.Context, identifier, dumpPath string) (*Response, error) {
	return c.SendCommand(ctx, Command{Command: "ZitiDump", Data: ZitiDumpData{Identifier: identifier, DumpPath: dumpPath}})
}

func (c *IPCClient) IpDump(ctx context.Context, dumpPath string) (*Response, error) {
	return c.SendCommand(ctx, Command{Command: "IpDump", Data: IpDumpData{DumpPath: dumpPath}})
}

func (c *IPCClient) EnableMFA(ctx context.Context, identifier string) (*Response, error) {
	return c.SendCommand(ctx, Command{Command: "EnableMFA", Data: EnableMFAData{Identifier: identifier}})
}

func (c *IPCClient) SubmitMFA(ctx context.Context, identifier, code string) (*Response, error) {
	return c.SendCommand(ctx, Command{Command: "SubmitMFA", Data: MFAData{Identifier: identifier, Code: code}})
}

func (c *IPCClient) VerifyMFA(ctx context.Context, identifier, code string) (*Response, error) {
	return c.SendCommand(ctx, Command{Command: "VerifyMFA", Data: MFAData{Identifier: identifier, Code: code}})
}

func (c *IPCClient) RemoveMFA(ctx context.Context, identifier, code string) (*Response, error) {
	return c.SendCommand(ctx, Command{Command: "RemoveMFA", Data: MFAData{Identifier: identifier, Code: code}})
}

func (c *IPCClient) GenerateMFACodes(ctx context.Context, identifier, code string) (*Response, error) {
	return c.SendCommand(ctx, Command{Command: "GenerateMFACodes", Data: MFAData{Identifier: identifier, Code: code}})
}

func (c *IPCClient) GetMFACodes(ctx context.Context, identifier, code string) (*Response, error) {
	return c.SendCommand(ctx, Command{Command: "GetMFACodes", Data: MFAData{Identifier: identifier, Code: code}})
}

func (c *IPCClient) UpdateInterfaceConfig(ctx context.Context, cfg InterfaceConfigData) (*Response, error) {
	return c.SendCommand(ctx, Command{Command: "UpdateInterfaceConfig", Data: cfg})
}

func (c *IPCClient) ExternalAuth(ctx context.Context, identifier, provider string) (*Response, error) {
	return c.SendCommand(ctx, Command{Command: "ExternalAuth", Data: ExternalAuthData{Identifier: identifier, Provider: provider}})
}

func (c *IPCClient) Status(ctx context.Context) (*Response, error) {
	return c.SendCommand(ctx, Command{Command: "Status"})
}

func (c *IPCClient) ListIdentities(ctx context.Context) (*Response, error) {
	return c.SendCommand(ctx, Command{Command: "ListIdentities"})
}

func (c *IPCClient) GetMetrics(ctx context.Context) (*Response, error) {
	return c.SendCommand(ctx, Command{Command: "GetMetrics"})
}

func (c *IPCClient) AddIdentity(ctx context.Context, data AddIdentityData) (*Response, error) {
	return c.SendCommand(ctx, Command{Command: "AddIdentity", Data: data})
}
