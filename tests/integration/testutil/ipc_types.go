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

import "testing"

// All IPC types live here. They model the JSON emitted/accepted by
// ziti-edge-tunnel's IPC handlers. Do not rename a JSON name without
// changing the handlers first.
//
//   ServiceFunction (base command) / IdentifierFunction, AddIdentityFunction, ... (typed commands)
//   ServiceResponse (base response) / AddIdentityResponse, ExternalAuthResponse, ... (typed responses)

// ---------------------------------------------------------------------------
// Payload structs: the Data field of each command.
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
	Identifier string `json:"Identifier,omitempty"`
	DumpPath   string `json:"DumpPath,omitempty"`
}

type IpDumpData struct {
	DumpPath string `json:"DumpPath,omitempty"`
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

func NewJwtIdentityData(name, jwt string) AddIdentityData {
	return AddIdentityData{
		IdentityFilename: name,
		JwtContent:       &jwt,
	}
}

func NewUrlIdentityData(name, url string, mode EnrollMode, provider ...string) AddIdentityData {
	data := AddIdentityData{
		IdentityFilename: name,
		ControllerURL:    &url,
		EnrollMode:       &mode,
	}
	// Provider applies only to cert/token enrollment, enroll-to-none omits it.
	if len(provider) > 0 {
		data.Provider = &provider[0]
	}
	return data
}

func NewCaIdentityData(name, caJwt, cert, key string) AddIdentityData {
	return AddIdentityData{
		IdentityFilename: name,
		JwtContent:       &caJwt,
		Certificate:      &cert,
		Key:              &key,
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
	Success bool   `json:"Success"`
	Error   string `json:"Error"`
	Code    int    `json:"Code"`

	t *testing.T
}

// AddIdentityResponse is returned by AddIdentity. Data carries the ext-auth URL
// only in enroll-to-cert/token mode; for enroll-to-none it is empty (the URL
// is delivered later via the ExternalAuthResponse to a separate command).
type AddIdentityResponse struct {
	ServiceResponse
	Data ExtAuth `json:"Data"`
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

// MFAEnrollmentResponse is returned by EnableMFA. Data carries the enrollment payload.
type MFAEnrollmentResponse struct {
	ServiceResponse
	Data MFAEnrollment `json:"Data"`
}

// MFARecoveryCodesResponse is returned by GetMFACodes and GenerateMFACodes.
type MFARecoveryCodesResponse struct {
	ServiceResponse
	Data MFARecoveryCodes `json:"Data"`
}

// IpDumpResponse is returned by IpDump. Data carries the full ip stack stats.
type IpDumpResponse struct {
	ServiceResponse
	Data IpStats `json:"Data"`
}

// ZitiDumpResponse is returned by ZitiDump. Data maps identifier to its text dump.
type ZitiDumpResponse struct {
	ServiceResponse
	Data map[string]string `json:"Data"`
}

// ---------------------------------------------------------------------------
// Inner Data shapes referenced by typed responses.
// ---------------------------------------------------------------------------

// IpMemPool mirrors tunnel_ip_mem_pool from ziti_tunnel.h.
type IpMemPool struct {
	Name  string `json:"Name"`
	Max   int    `json:"Max"`
	Used  int    `json:"Used"`
	Avail int    `json:"Avail"`
}

// IpConn mirrors tunnel_ip_conn from ziti_tunnel.h.
type IpConn struct {
	Protocol   string `json:"Protocol"`
	LocalIP    string `json:"LocalIP"`
	LocalPort  int    `json:"LocalPort"`
	RemoteIP   string `json:"RemoteIP"`
	RemotePort int    `json:"RemotePort"`
	State      string `json:"State"`
	Service    string `json:"Service"`
}

// IpStats mirrors tunnel_ip_stats from ziti_tunnel.h.
type IpStats struct {
	Pools       []IpMemPool `json:"Pools"`
	Connections []IpConn    `json:"Connections"`
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

type Identity struct {
	Name             string    `json:"Name"`
	Identifier       string    `json:"Identifier"`
	FingerPrint      string    `json:"FingerPrint"`
	Active           bool      `json:"Active"`
	NeedsExtAuth     bool      `json:"NeedsExtAuth"`
	ExtAuthProviders []string  `json:"ExtAuthProviders"`
	MfaEnabled       bool      `json:"MfaEnabled"`
	MfaNeeded        bool      `json:"MfaNeeded"`
	Services         []Service `json:"Services"`
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
	PcapInterface  string         `json:"PcapInterface"`
	TapInfo        TapInfo        `json:"TapInfo"`
	ConfigDir      string         `json:"ConfigDir"`
}

type MFAEnrollment struct {
	Identifier      string   `json:"Identifier"`
	IsVerified      bool     `json:"IsVerified"`
	ProvisioningUrl string   `json:"ProvisioningUrl"`
	RecoveryCodes   []string `json:"RecoveryCodes"`
}

type MFARecoveryCodes struct {
	Identifier    string   `json:"Identifier"`
	RecoveryCodes []string `json:"RecoveryCodes"`
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
//     ActionEvent : StatusEvent { Action, Identifier, Fingerprint }
//       IdentityEvent    { Id }
//       MfaEvent         { Successful, Error, ProvisioningUrl, RecoveryCodes }
//       BulkServiceEvent { AddedServices, RemovedServices }
//     TunnelStatusEvent : StatusEvent { Status }
// ---------------------------------------------------------------------------

// StatusEvent is the base shape for daemon events.
type StatusEvent struct {
	Op string `json:"Op"`
}

// ActionEvent adds Action, Identifier and Fingerprint to StatusEvent; most event
// subclasses extend it. Fingerprint is the identity name, and Op:"controller"
// (connected, disconnected) arrives as a bare ActionEvent.
type ActionEvent struct {
	StatusEvent
	Action      string `json:"Action"`
	Identifier  string `json:"Identifier"`
	Fingerprint string `json:"Fingerprint"`
}

// IdentityEvent fires on Op:"identity" (needs_ext_login, added, updated, removed).
type IdentityEvent struct {
	ActionEvent
	Id Identity `json:"Id"`

	t *testing.T
}

// MfaEvent fires on Op:"mfa" (enrollment_required, enrollment_challenge,
// enrollment_verification, mfa_auth_status, auth_challenge, enrollment_remove).
type MfaEvent struct {
	ActionEvent
	Successful      bool     `json:"Successful"`
	Error           string   `json:"Error"`
	ProvisioningUrl string   `json:"ProvisioningUrl"`
	RecoveryCodes   []string `json:"RecoveryCodes"`

	t *testing.T
}

// TunnelStatusEvent carries the full tunnel status (no Action; extends StatusEvent directly).
// Op is "status" on connect and "shutdown" on the way down.
type TunnelStatusEvent struct {
	StatusEvent
	Status TunnelStatus `json:"Status"`
}

type Service struct {
	Id                     string         `json:"Id"`
	Name                   string         `json:"Name"`
	Protocols              []string       `json:"Protocols"`
	Addresses              []Address      `json:"Addresses"`
	AllowedSourceAddresses []Address      `json:"AllowedSourceAddresses"`
	Ports                  []PortRange    `json:"Ports"`
	OwnsIntercept          bool           `json:"OwnsIntercept"`
	PostureChecks          []PostureCheck `json:"PostureChecks"`
	IsAccessible           bool           `json:"IsAccessible"`
	Timeout                int            `json:"Timeout"`
	TimeoutRemaining       int            `json:"TimeoutRemaining"`
	Permissions            Permissions    `json:"Permissions"`
}

type Permissions struct {
	Bind bool `json:"Bind"`
	Dial bool `json:"Dial"`
}

type Address struct {
	IsHost   bool   `json:"IsHost"`
	HostName string `json:"HostName"`
	IP       string `json:"IP"`
	Prefix   int    `json:"Prefix"`
}

type PortRange struct {
	High int `json:"High"`
	Low  int `json:"Low"`
}

type PostureCheck struct {
	IsPassing        bool   `json:"IsPassing"`
	QueryType        string `json:"QueryType"`
	Id               string `json:"Id"`
	Timeout          int    `json:"Timeout"`
	TimeoutRemaining int    `json:"TimeoutRemaining"`
}

// BulkServiceEvent fires on Op:"bulkservice" when an identity's authorized service
// set changes; AddedServices/RemovedServices carry the delta.
type BulkServiceEvent struct {
	ActionEvent
	AddedServices   []Service `json:"AddedServices"`
	RemovedServices []Service `json:"RemovedServices"`
}
