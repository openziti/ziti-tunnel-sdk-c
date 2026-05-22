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

import "encoding/json"

// All IPC wire types live here. Mirrors the wire JSON emitted/accepted by
// ziti-edge-tunnel's IPC handlers (defined in lib/ziti-tunnel-cbs/include/ziti/ziti_tunnel_cbs.h).
// JSON tags match the C TUNNEL_* macros exactly; do not rename them without
// changing the handlers first.
//
//   ServiceFunction (base command) / IdentifierFunction, AddIdentityFunction, ... (typed commands)
//   ServiceResponse (base response) / AddIdentityResponse, ExternalAuthResponse, ... (typed responses)

// ---------------------------------------------------------------------------
// Payload structs — the Data field of each command.
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Constructors for the base ServiceFunction and per-command Data payloads.
// ---------------------------------------------------------------------------

func NewServiceFunction(command string) ServiceFunction {
	return ServiceFunction{
		Command: command,
	}
}

func NewIdentifierData(identifier string) IdentifierData {
	return IdentifierData{
		Identifier: identifier,
	}
}

func NewIdentityOnOffData(identifier string, onOff bool) IdentityOnOffData {
	return IdentityOnOffData{
		Identifier: identifier,
		OnOff:      onOff,
	}
}

func NewSetLogLevelData(level string) SetLogLevelData {
	return SetLogLevelData{
		Level: level,
	}
}

func NewZitiDumpData(identifier, dumpPath string) ZitiDumpData {
	return ZitiDumpData{
		Identifier: identifier,
		DumpPath:   dumpPath,
	}
}

func NewIpDumpData(dumpPath string) IpDumpData {
	return IpDumpData{
		DumpPath: dumpPath,
	}
}

func NewMFAData(identifier, code string) MFAData {
	return MFAData{
		Identifier: identifier,
		Code:       code,
	}
}

func NewExternalAuthData(identifier, provider string) ExternalAuthData {
	return ExternalAuthData{
		Identifier: identifier,
		Provider:   provider,
	}
}

// ---------------------------------------------------------------------------
// Commands (ServiceFunction base + typed wrappers).
// ---------------------------------------------------------------------------

// ServiceFunction is the base IPC command
type ServiceFunction struct {
	Command string `json:"Command"`
}

type IdentifierFunction struct {
	ServiceFunction
	Data IdentifierData `json:"Data"`
}

type IdentityOnOffFunction struct {
	ServiceFunction
	Data IdentityOnOffData `json:"Data"`
}

type SetLogLevelFunction struct {
	ServiceFunction
	Data SetLogLevelData `json:"Data"`
}

type ZitiDumpFunction struct {
	ServiceFunction
	Data ZitiDumpData `json:"Data"`
}

type IpDumpFunction struct {
	ServiceFunction
	Data IpDumpData `json:"Data"`
}

type MFAFunction struct {
	ServiceFunction
	Data MFAData `json:"Data"`
}

type InterfaceConfigFunction struct {
	ServiceFunction
	Data InterfaceConfigData `json:"Data"`
}

type ExternalAuthFunction struct {
	ServiceFunction
	Data ExternalAuthData `json:"Data"`
}

type AddIdentityFunction struct {
	ServiceFunction
	Data AddIdentityData `json:"Data"`
}

// ---------------------------------------------------------------------------
// Responses (ServiceResponse base + typed wrappers).
// ---------------------------------------------------------------------------

type ServiceResponse struct {
	Code    int    `json:"Code,omitempty"`
	Message string `json:"Message,omitempty"`
	Error   string `json:"Error,omitempty"`
}

// Success returns true when the daemon reports a non-error code.
func (r *ServiceResponse) Success() bool { return r.Code == 0 }

// AddIdentityResponse is returned by AddIdentity. Data carries the ext-auth URL
// only in enroll-to-cert/token mode; for enroll-to-none it is empty (the URL
// is delivered later via the ExternalAuthResponse to a separate command).
type AddIdentityResponse struct {
	ServiceResponse
	Data ExtAuth `json:"Data,omitempty"`
}

// ExternalAuthResponse is returned by ExternalAuth. Data carries the ext-auth URL.
type ExternalAuthResponse struct {
	ServiceResponse
	Data ExtAuth `json:"Data"`
}

// StatusUpdateResponse is returned by Status. Data carries the full tunnel status.
type StatusUpdateResponse struct {
	ServiceResponse
	Data TunnelStatus `json:"Data"`
}

// StatusRawResponse is the raw-bytes variant of StatusUpdateResponse for the
// wire-contract test that needs to inspect the daemon's exact top-level keys.
type StatusRawResponse struct {
	ServiceResponse
	Data json.RawMessage `json:"Data"`
}

// MFAEnrollmentResponse is returned by EnableMFA. Data carries the enrollment payload.
type MFAEnrollmentResponse struct {
	ServiceResponse
	Data MFAEnrollment `json:"Data"`
}

// ---------------------------------------------------------------------------
// Inner Data shapes referenced by typed responses.
// ---------------------------------------------------------------------------

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

// Identity mirrors ZDEW's Identity class — used both inside Event payloads
// and inside TunnelStatus.Identities.
type Identity struct {
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
	Active         bool           `json:"Active"`
	Duration       int64          `json:"Duration"`
	StartTime      string         `json:"StartTime"`
	Identities     []Identity     `json:"Identities"`
	IpInfo         IpInfo         `json:"IpInfo"`
	LogLevel       string         `json:"LogLevel"`
	ServiceVersion ServiceVersion `json:"ServiceVersion"`
	TunIpv4        string         `json:"TunIpv4"`
	TunIpv4Mask    int            `json:"TunIpv4Mask"`
	AddDns         bool           `json:"AddDns"`
	ApiPageSize    int            `json:"ApiPageSize"`
	TunName        string         `json:"TunName"`
	L2Enabled      bool           `json:"L2Enabled"`
	TapInfo        TapInfo        `json:"TapInfo"`
	ConfigDir      string         `json:"ConfigDir"`
}

type MFAEnrollment struct {
	Identifier      string   `json:"Identifier"`
	IsVerified      bool     `json:"IsVerified"`
	ProvisioningUrl string   `json:"ProvisioningUrl"`
	RecoveryCodes   []string `json:"RecoveryCodes"`
}

// ExtAuth is the parsed payload of an ExternalAuth response (and the
// AddIdentity-with-EnrollMode response): the URL the user must open to begin
// the OIDC flow.
type ExtAuth struct {
	Identifier string `json:"identifier"`
	URL        string `json:"url"`
}

// ---------------------------------------------------------------------------
// Event pipe types
//
//   StatusEvent { Op }
//     ActionEvent : StatusEvent { Action }
//       IdentityEvent       { Id }
//       ControllerEvent     { Identifier }
//       MfaEvent            { Identifier, Successful, ProvisioningUrl, RecoveryCodes }
//       AuthenticationEvent { Identifier }
//       LogLevelEvent       { LogLevel }
//     TunnelStatusEvent : StatusEvent { Status }
//     MetricsEvent      : StatusEvent { Identities[] }
// ---------------------------------------------------------------------------

// StatusEvent is the base wire shape for daemon events.
type StatusEvent struct {
	Op string `json:"Op"`
}

// ActionEvent adds Action to StatusEvent; most event subclasses extend it.
type ActionEvent struct {
	StatusEvent
	Action string `json:"Action"`
}

// IdentityEvent fires on Op:"identity" (needs_ext_login, added, updated, removed).
type IdentityEvent struct {
	ActionEvent
	Id Identity `json:"Id"`
}

// ControllerEvent fires on Op:"controller" (connected, disconnected).
type ControllerEvent struct {
	ActionEvent
	Identifier string `json:"Identifier"`
}

// MfaEvent fires on Op:"mfa" (enrollment_verification, mfa_auth_status,
// auth_challenge, enrollment_remove).
type MfaEvent struct {
	ActionEvent
	Identifier      string   `json:"Identifier"`
	Successful      bool     `json:"Successful"`
	ProvisioningUrl string   `json:"ProvisioningUrl,omitempty"`
	RecoveryCodes   []string `json:"RecoveryCodes,omitempty"`
}

// AuthenticationEvent fires on authentication transitions.
type AuthenticationEvent struct {
	ActionEvent
	Identifier string `json:"Identifier"`
}

// LogLevelEvent fires when the daemon reports a log-level change.
type LogLevelEvent struct {
	ActionEvent
	LogLevel string `json:"LogLevel"`
}

// TunnelStatusEvent carries the full tunnel status (no Action; extends StatusEvent directly).
type TunnelStatusEvent struct {
	StatusEvent
	Status TunnelStatus `json:"Status"`
}

// MetricsEvent carries per-identity metric snapshots.
type MetricsEvent struct {
	StatusEvent
	Identities []Identity `json:"Identities"`
}
