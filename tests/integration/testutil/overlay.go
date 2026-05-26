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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	adminUsername   = "admin"
	adminPassword   = "admin"
	overlayCtrlPort = 1280
	overlayRtrPort  = 3022
)

type Overlay struct {
	ZitiBin             string
	Home                string
	ZitiMajor           int
	ZitiMinor           int
	ShowZitiCliCommands bool

	cmd     *exec.Cmd
	stdout  *syncBuffer
	stderr  *syncBuffer
	logFile *os.File
	Done    chan error
}

// Start launches `ziti edge quickstart` against o.Home and waits until the
// overlay is ready. Callers must defer Stop().
func (o *Overlay) Start() error {
	warnIfPortBound(overlayCtrlPort)
	warnIfPortBound(overlayRtrPort)
	log.Printf("overlay: mkdir home %s", o.Home)
	if err := os.MkdirAll(o.Home, 0o755); err != nil {
		return fmt.Errorf("mkdir home: %w", err)
	}

	args := []string{
		"edge", "quickstart",
		"--home=" + o.Home,
		"--ctrl-address=localhost",
		fmt.Sprintf("--ctrl-port=%d", overlayCtrlPort),
		"--router-address=localhost",
		fmt.Sprintf("--router-port=%d", overlayRtrPort),
	}
	log.Printf("overlay: starting %s %s", o.ZitiBin, strings.Join(args, " "))
	o.cmd = exec.Command(o.ZitiBin, args...)
	o.cmd.Env = append(os.Environ(),
		"ZITI_CONFIG_DIR="+filepath.Join(o.Home, "cli-config"),
		// PFXLOG_NO_JSON makes ziti's stderr human-readable for test log output.
		"PFXLOG_NO_JSON=true",
	)
	logPath := filepath.Join(o.Home, "quickstart-logs", "quickstart.log")
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		return fmt.Errorf("mkdir quickstart log dir: %w", err)
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open quickstart log file: %w", err)
	}
	log.Printf("overlay: quickstart log %s", logPath)
	o.stdout = newSyncBuffer()
	o.stderr = newSyncBuffer()
	o.cmd.Stdout = io.MultiWriter(o.stdout, logFile)
	o.cmd.Stderr = io.MultiWriter(o.stderr, logFile)

	if err := o.cmd.Start(); err != nil {
		_ = logFile.Close()
		return fmt.Errorf("start quickstart: %w", err)
	}

	go func() { o.Done <- o.cmd.Wait() }()

	if err := o.waitUntilReady(); err != nil {
		o.Stop()
		return fmt.Errorf("overlay not ready: %w\n%s", err, o.Logs())
	}

	log.Printf("overlay: probing ziti version")
	major, minor, err := probeZitiVersion(o.ZitiBin)
	if err != nil {
		o.Stop()
		return fmt.Errorf("probe ziti version: %w", err)
	}
	o.ZitiMajor = major
	o.ZitiMinor = minor
	log.Printf("overlay: ready (ziti v%d.%d)", major, minor)
	return nil
}

// warnIfPortBound logs a warning if something is already listening on localhost:port.
// It does not fail; the subsequent ziti quickstart will surface the real bind error.
func warnIfPortBound(port uint16) {
	addr := fmt.Sprintf("localhost:%d", port)
	conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err != nil {
		return
	}
	_ = conn.Close()
	log.Printf("WARNING: port %d is already bound (%s); ziti quickstart will not be able to start until it is released", port, addr)
}

func probeZitiVersion(zitiBin string) (int, int, error) {
	out, err := exec.Command(zitiBin, "--version").Output()
	if err != nil {
		return 0, 0, fmt.Errorf("run %s --version: %w", zitiBin, err)
	}
	version := strings.TrimPrefix(strings.TrimSpace(string(out)), "v")
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return 0, 0, fmt.Errorf("parse ziti version from %q", string(out))
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("parse major from %q: %w", parts[0], err)
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("parse minor from %q: %w", parts[1], err)
	}
	return major, minor, nil
}

func (o *Overlay) ControllerHostPort() string {
	return fmt.Sprintf("https://localhost:%d", overlayCtrlPort)
}

func (o *Overlay) CATrusted() bool {
	hostport := fmt.Sprintf("localhost:%d", overlayCtrlPort)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", hostport, nil)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// OSCAStrings returns OS-specific install and cleanup shell commands for this
// overlay's CA. Both are "" when the OS has no recipe.
func (o *Overlay) OSCAStrings() (install, cleanup string) {
	caPath := filepath.Join(o.Home, "pki", "root-ca", "certs", "root-ca.cert")
	switch runtime.GOOS {
	case "windows":
		install = fmt.Sprintf(`Import-Certificate -FilePath "%s" -CertStoreLocation Cert:\LocalMachine\Root`, caPath)
		cleanup = fmt.Sprintf(`$c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 "%s"; Get-ChildItem Cert:\LocalMachine\Root | ? Thumbprint -eq $c.Thumbprint | Remove-Item`, caPath)
	case "darwin":
		install = fmt.Sprintf(`sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s`, caPath)
		cleanup = fmt.Sprintf(`sudo security delete-certificate -Z $(openssl x509 -in %s -noout -fingerprint -sha1 | sed 's/.*=//' | tr -d ':') /Library/Keychains/System.keychain`, caPath)
	case "linux":
		install = fmt.Sprintf(`sudo cp %s /usr/local/share/ca-certificates/ziti-test.crt && sudo update-ca-certificates`, caPath)
		cleanup = `sudo rm /usr/local/share/ca-certificates/ziti-test.crt && sudo update-ca-certificates --fresh`
	}
	return
}

// RequireCATrusted skips the test (with OS-specific install/cleanup
// instructions) if the overlay's CA isn't in the calling OS's trust store.
func (o *Overlay) RequireCATrusted(t *testing.T) {
	if o.CATrusted() {
		return
	}
	caPath := filepath.Join(o.Home, "pki", "root-ca", "certs", "root-ca.cert")
	install, cleanup := o.OSCAStrings()
	if install == "" {
		t.Skipf(`tests need the CA at %s in OS trust (no install instructions for %s).

  Current overlay home: %s
  Pass a durable path with -test-home so the PKI (and this trust install) persists across runs.`, caPath, runtime.GOOS, o.Home)
		return
	}
	t.Skipf(`tests need the test overlay's CA in OS trust.

  Current overlay home: %s
  Pass a durable path with -test-home so the PKI (and this trust install) persists across runs.

  Install:
  %s

  Cleanup when done:
  %s`, o.Home, install, cleanup)
}

// A surviving overlay holds the controller/router ports and breaks subsequent
// runs, so abort hard rather than let an orphan hide.
func (o *Overlay) Stop() {
	if o == nil || o.cmd == nil || o.cmd.Process == nil {
		return
	}
	if o.logFile != nil {
		defer func() { _ = o.logFile.Close() }()
	}
	if o.cmd.Process == nil {
		return
	}
	pid := o.cmd.Process.Pid
	if err := o.cmd.Process.Kill(); err != nil {
		log.Printf("overlay pid %d kill: %v", pid, err)
	}
	for i := 0; i < 120; i++ {
		time.Sleep(500 * time.Millisecond)
		if proc, err := os.FindProcess(pid); err != nil || proc == nil {
			return
		}
		if err := o.cmd.Process.Signal(syscall.Signal(0)); err != nil {
			return
		}
	}
	log.Fatalf("overlay pid %d did not exit within 60s of Kill; orphan likely, aborting test run", pid)
}

func (o *Overlay) Logs() string {
	return fmt.Sprintf("--- ziti stdout ---\n%s\n--- ziti stderr ---\n%s",
		o.stdout.String(), o.stderr.String())
}

// CreateIdentityJWT provisions a new (non-admin) identity and returns its enrollment JWT content.
func (o *Overlay) CreateIdentityJWT(name string) (string, error) {
	jwtPath := filepath.Join(o.Home, name+".jwt")
	if _, err := o.execZiti("edge", "create", "identity", name, "-o", jwtPath); err != nil {
		return "", fmt.Errorf("create identity %s: %w", name, err)
	}
	content, err := os.ReadFile(jwtPath)
	if err != nil {
		return "", fmt.Errorf("read jwt %s: %w", jwtPath, err)
	}
	return string(bytes.TrimSpace(content)), nil
}

func (o *Overlay) DeleteIdentity(name string) error {
	if _, err := o.execZiti("edge", "delete", "identity", name); err != nil {
		return fmt.Errorf("delete identity %s: %w", name, err)
	}
	return nil
}

func (o *Overlay) CreateAuthPolicyRequiringTOTP(name string) error {
	if _, err := o.execZiti("edge", "create", "auth-policy", name,
		"--primary-cert-allowed",
		"--secondary-req-totp"); err != nil {
		return fmt.Errorf("create auth policy %s: %w", name, err)
	}
	return nil
}

func (o *Overlay) CreateIdentityJWTWithAuthPolicy(name, authPolicy string) (string, error) {
	jwtPath := filepath.Join(o.Home, name+".jwt")
	if _, err := o.execZiti("edge", "create", "identity", name,
		"-P", authPolicy,
		"-o", jwtPath); err != nil {
		return "", fmt.Errorf("create identity %s with policy %s: %w", name, authPolicy, err)
	}
	content, err := os.ReadFile(jwtPath)
	if err != nil {
		return "", fmt.Errorf("read jwt %s: %w", jwtPath, err)
	}
	return string(bytes.TrimSpace(content)), nil
}

// ExtJwtSignerSpec describes an external JWT signer to register on the
// controller. EnrollToCert / EnrollToToken set the matching ziti 2.0+ flags.
type ExtJwtSignerSpec struct {
	Name          string
	Issuer        string
	JWKS          string
	ClientID      string
	Claim         string
	Scopes        []string
	EnrollToCert  bool
	EnrollToToken bool
}

// CreateExtJwtSigner registers an ext-jwt-signer on the controller and returns
// its assigned ID.
func (o *Overlay) CreateExtJwtSigner(t *testing.T, spec ExtJwtSignerSpec) string {
	t.Logf("creating ext-jwt-signer %q (issuer=%s clientID=%s enrollToCert=%t enrollToToken=%t)", spec.Name, spec.Issuer, spec.ClientID, spec.EnrollToCert, spec.EnrollToToken)
	args := []string{
		"edge", "create", "ext-jwt-signer", spec.Name, spec.Issuer,
		"--jwks-endpoint", spec.JWKS,
		"--audience", spec.ClientID,
		"--client-id", spec.ClientID,
		"--external-auth-url", spec.Issuer,
	}
	if spec.Claim != "" {
		args = append(args, "--claims-property", spec.Claim)
	}
	for _, s := range spec.Scopes {
		args = append(args, "--scopes", s)
	}
	if spec.EnrollToCert {
		args = append(args, "--enroll-to-cert")
	}
	if spec.EnrollToToken {
		args = append(args, "--enroll-to-token")
	}
	out, err := o.execZiti(args...)
	require.NoError(t, err, "create ext-jwt-signer %s", spec.Name)
	id := string(bytes.TrimSpace(out))
	t.Logf("ext-jwt-signer %q created with id=%s", spec.Name, id)
	return id
}

// FindExtJwtSignerId returns the id of the ext-jwt-signer with the given name
// and whether it exists.
func (o *Overlay) FindExtJwtSignerId(t *testing.T, name string) (string, bool) {
	out, err := o.execZiti("edge", "list", "ext-jwt-signers", fmt.Sprintf("name=%q", name), "-j")
	require.NoError(t, err, "list ext-jwt-signers name=%s", name)
	var resp struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(out, &resp), "parse ext-jwt-signers list for %s", name)
	if len(resp.Data) == 0 {
		return "", false
	}
	return resp.Data[0].ID, true
}

// UpdateExtJwtSigner sends `ziti edge update ext-jwt-signer <name>` with the
// fields supplied. Non-empty strings/slices are forwarded as their matching
// flag; EnrollToCert and EnrollToToken are always sent because false is a
// meaningful authoritative state and the only way to flip a previously-enabled
// flag back off.
func (o *Overlay) UpdateExtJwtSigner(t *testing.T, name string, spec ExtJwtSignerSpec) {
	t.Logf("updating ext-jwt-signer %q (enrollToCert=%t enrollToToken=%t)", name, spec.EnrollToCert, spec.EnrollToToken)
	args := []string{"edge", "update", "ext-jwt-signer", name}
	if spec.Name != "" {
		args = append(args, "--name", spec.Name)
	}
	if spec.Issuer != "" {
		args = append(args, "--issuer", spec.Issuer, "--external-auth-url", spec.Issuer)
	}
	if spec.JWKS != "" {
		args = append(args, "--jwks-endpoint", spec.JWKS)
	}
	if spec.ClientID != "" {
		args = append(args, "--audience", spec.ClientID, "--client-id", spec.ClientID)
	}
	if spec.Claim != "" {
		args = append(args, "--claims-property", spec.Claim)
	}
	for _, s := range spec.Scopes {
		args = append(args, "--scopes", s)
	}
	args = append(args, fmt.Sprintf("--enroll-to-cert=%t", spec.EnrollToCert))
	args = append(args, fmt.Sprintf("--enroll-to-token=%t", spec.EnrollToToken))
	_, err := o.execZiti(args...)
	require.NoError(t, err, "update ext-jwt-signer %s", name)
	t.Logf("ext-jwt-signer %q updated", name)
}

// CreateAuthPolicyForExtJwt creates an auth policy whose primary auth method
// is the ext-jwt-signer set with the given IDs. Pass one or more signer IDs.
func (o *Overlay) CreateAuthPolicyForExtJwt(t *testing.T, name string, signerIDs ...string) {
	t.Logf("creating auth policy %q with %d ext-jwt-signer(s)", name, len(signerIDs))
	args := []string{"edge", "create", "auth-policy", name, "--primary-ext-jwt-allowed"}
	for _, id := range signerIDs {
		args = append(args, "--primary-ext-jwt-allowed-signers", id)
	}
	_, err := o.execZiti(args...)
	require.NoError(t, err, "create auth policy %s", name)
	t.Logf("auth policy %q created", name)
}

// CreateIdentityWithExternalId provisions a non-admin identity stamped with
// externalId so the controller can match it against the "sub" claim of an
// ext-jwt-signer-issued JWT. If authPolicy is non-empty the identity is bound
// to that policy; otherwise it falls into the controller's default policy.
func (o *Overlay) CreateIdentityWithExternalId(t *testing.T, name, externalID, authPolicy string) {
	policyDesc := authPolicy
	if policyDesc == "" {
		policyDesc = "default"
	}
	t.Logf("creating controller identity %q with externalId=%q bound to auth policy %q", name, externalID, policyDesc)
	args := []string{"edge", "create", "identity", name, "--external-id", externalID}
	if authPolicy != "" {
		args = append(args, "-P", authPolicy)
	}
	_, err := o.execZiti(args...)
	require.NoError(t, err, "create identity %s with externalId %s", name, externalID)
	t.Logf("controller identity %q created", name)
}

// CreateUpdbUser creates a non-admin identity with a UPDB authenticator so the
// identity can authenticate via the controller's built-in OIDC username/password
// login. Returns the new identity's controller ID.
func (o *Overlay) CreateUpdbUser(name, username, password string) (string, error) {
	out, err := o.execZiti("edge", "create", "identity", name, "-j")
	if err != nil {
		return "", fmt.Errorf("create identity %s: %w", name, err)
	}
	var resp struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		return "", fmt.Errorf("parse create identity %s response: %w", name, err)
	}
	if resp.Data.ID == "" {
		return "", fmt.Errorf("create identity %s returned empty id", name)
	}
	if _, err := o.execZiti("edge", "create", "authenticator", "updb", resp.Data.ID, username, password); err != nil {
		return "", fmt.Errorf("create updb authenticator for %s: %w", name, err)
	}
	return resp.Data.ID, nil
}

// DeleteExtJwtSigner removes an ext-jwt-signer by name.
func (o *Overlay) DeleteExtJwtSigner(name string) error {
	if _, err := o.execZiti("edge", "delete", "ext-jwt-signer", name); err != nil {
		return fmt.Errorf("delete ext-jwt-signer %s: %w", name, err)
	}
	return nil
}

// DeleteAuthPolicy removes an auth policy by name.
func (o *Overlay) DeleteAuthPolicy(name string) error {
	if _, err := o.execZiti("edge", "delete", "auth-policy", name); err != nil {
		return fmt.Errorf("delete auth policy %s: %w", name, err)
	}
	return nil
}

// CreateHostConfigV1 creates a host.v1 config that forwards to forwardAddr:forwardPort.
func (o *Overlay) CreateHostConfigV1(name, protocol, forwardAddr string, forwardPort int) error {
	body, err := json.Marshal(struct {
		Protocol string `json:"protocol"`
		Address  string `json:"address"`
		Port     int    `json:"port"`
	}{Protocol: protocol, Address: forwardAddr, Port: forwardPort})
	if err != nil {
		return err
	}
	if _, err := o.execZiti("edge", "create", "config", name, "host.v1", string(body)); err != nil {
		return fmt.Errorf("create host config %s: %w", name, err)
	}
	return nil
}

// CreateInterceptConfigV1 creates an intercept.v1 config matching the given protocols, addresses, and port range.
func (o *Overlay) CreateInterceptConfigV1(name string, protocols, addresses []string, portLow, portHigh int) error {
	body, err := json.Marshal(struct {
		Protocols  []string `json:"protocols"`
		Addresses  []string `json:"addresses"`
		PortRanges []struct {
			Low  int `json:"low"`
			High int `json:"high"`
		} `json:"portRanges"`
	}{
		Protocols: protocols,
		Addresses: addresses,
		PortRanges: []struct {
			Low  int `json:"low"`
			High int `json:"high"`
		}{{Low: portLow, High: portHigh}},
	})
	if err != nil {
		return err
	}
	if _, err := o.execZiti("edge", "create", "config", name, "intercept.v1", string(body)); err != nil {
		return fmt.Errorf("create intercept config %s: %w", name, err)
	}
	return nil
}

// CreateService creates a service that references the given configs.
func (o *Overlay) CreateService(name string, configs []string) error {
	args := []string{"edge", "create", "service", name, "--configs", strings.Join(configs, ",")}
	if _, err := o.execZiti(args...); err != nil {
		return fmt.Errorf("create service %s: %w", name, err)
	}
	return nil
}

// CreateBindServicePolicy creates a Bind service policy granting identityName access to serviceName.
func (o *Overlay) CreateBindServicePolicy(name, identityName, serviceName string) error {
	if _, err := o.execZiti("edge", "create", "service-policy", name, "Bind",
		"--identity-roles", "@"+identityName,
		"--service-roles", "@"+serviceName,
		"--semantic", "AnyOf",
	); err != nil {
		return fmt.Errorf("create bind policy %s: %w", name, err)
	}
	return nil
}

// CreateDialServicePolicy creates a Dial service policy granting identityName access to serviceName.
func (o *Overlay) CreateDialServicePolicy(name, identityName, serviceName string) error {
	if _, err := o.execZiti("edge", "create", "service-policy", name, "Dial",
		"--identity-roles", "@"+identityName,
		"--service-roles", "@"+serviceName,
		"--semantic", "AnyOf",
	); err != nil {
		return fmt.Errorf("create dial policy %s: %w", name, err)
	}
	return nil
}

// DeleteServicePolicy deletes a service policy by name.
func (o *Overlay) DeleteServicePolicy(name string) error {
	if _, err := o.execZiti("edge", "delete", "service-policy", name); err != nil {
		return fmt.Errorf("delete service policy %s: %w", name, err)
	}
	return nil
}

// DeleteService deletes a service by name.
func (o *Overlay) DeleteService(name string) error {
	if _, err := o.execZiti("edge", "delete", "service", name); err != nil {
		return fmt.Errorf("delete service %s: %w", name, err)
	}
	return nil
}

// DeleteConfig deletes a config by name.
func (o *Overlay) DeleteConfig(name string) error {
	if _, err := o.execZiti("edge", "delete", "config", name); err != nil {
		return fmt.Errorf("delete config %s: %w", name, err)
	}
	return nil
}

func (o *Overlay) waitUntilReady() error {
	if err := o.waitForControllerPort(); err != nil {
		return err
	}
	log.Printf("overlay: attempting admin login at %s", o.ControllerHostPort())
	attempts := 0
	for {
		attempts++
		if _, err := o.execZiti("edge", "login", o.ControllerHostPort(),
			"-u", adminUsername, "-p", adminPassword, "--yes"); err == nil {
			log.Printf("overlay: admin login OK after %d attempt(s)", attempts)
			return nil
		} else {
			log.Printf("overlay: admin login attempt %d failed, retrying", attempts)
		}
		select {
		case err := <-o.Done:
			return fmt.Errorf("quickstart exited before becoming ready: %v", err)
		case <-time.After(1 * time.Second):
		}
	}
}

func (o *Overlay) waitForControllerPort() error {
	addr := fmt.Sprintf("localhost:%d", overlayCtrlPort)
	log.Printf("overlay: waiting for controller TCP port %s", addr)
	for {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			_ = conn.Close()
			log.Printf("overlay: controller port %s open", addr)
			return nil
		}
		select {
		case exitErr := <-o.Done:
			return fmt.Errorf("quickstart exited before port %d opened: %v", overlayCtrlPort, exitErr)
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func (o *Overlay) execZiti(args ...string) ([]byte, error) {
	cmd := exec.Command(o.ZitiBin, args...)
	cmd.Env = append(os.Environ(),
		"ZITI_CONFIG_DIR="+filepath.Join(o.Home, "cli-config"),
	)
	var stdout, stderr syncBuffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if o.ShowZitiCliCommands {
		fmt.Println("COMMAND: " + cmd.String())
	}
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s %v: %w\nstdout: %s\nstderr: %s",
			o.ZitiBin, args, err, stdout.String(), stderr.String())
	}
	if o.ShowZitiCliCommands {
		fmt.Println("COMMAND RESULT: \n" + stdout.String())
	}
	return []byte(stdout.String()), nil
}

// PurgeIdentities deletes every identity whose name contains prefix.
func (o *Overlay) PurgeIdentities(prefix string) error {
	return o.deleteWhere("identities", prefix)
}

// PurgeIdentityByExternalId deletes the identity whose externalId equals the given value.
// Needed for enroll-to-cert/token tests since the OIDC flow auto-provisions identities with
// names derived from JWT claims (not Test*), so the prefix purge misses them.
func (o *Overlay) PurgeIdentityByExternalId(externalId string) error {
	filter := fmt.Sprintf(`externalId = "%s"`, externalId)
	if _, err := o.execZiti("edge", "delete", "identities", "where", filter); err != nil {
		return fmt.Errorf("delete identity where %s: %w", filter, err)
	}
	return nil
}

// PurgeAuthPolicies deletes every auth policy whose name contains prefix.
func (o *Overlay) PurgeAuthPolicies(prefix string) error {
	return o.deleteWhere("auth-policies", prefix)
}

// PurgeExtJwtSigners deletes every ext-jwt-signer whose name contains prefix.
func (o *Overlay) PurgeExtJwtSigners(prefix string) error {
	return o.deleteWhere("ext-jwt-signers", prefix)
}

func (o *Overlay) deleteWhere(entity, prefix string) error {
	filter := fmt.Sprintf(`name contains "%s" limit none`, prefix)
	if _, err := o.execZiti("edge", "delete", entity, "where", filter); err != nil {
		return fmt.Errorf("delete %s where %s: %w", entity, filter, err)
	}
	return nil
}

// WaitForClusterLeader blocks until the controller's raft cluster has elected a
// leader so subsequent writes do not fail with CLUSTER_NO_LEADER. No-op for ziti < 2.0.
// Retries forever; rely on the overall test timeout if the cluster wedges.
func (o *Overlay) WaitForClusterLeader() error {
	if o.ZitiMajor < 2 {
		return nil
	}
	log.Printf("overlay: waiting for cluster leader (ziti v%d.%d)", o.ZitiMajor, o.ZitiMinor)
	attempts := 0
	for {
		attempts++
		out, err := o.execZiti("ops", "cluster", "list", "-j")
		if err == nil {
			var resp struct {
				Data []struct {
					Leader *bool `json:"leader"`
				} `json:"data"`
			}
			if json.Unmarshal(out, &resp) == nil {
				for _, m := range resp.Data {
					if m.Leader != nil && *m.Leader {
						log.Printf("overlay: cluster leader elected after %d attempt(s)", attempts)
						return nil
					}
				}
			}
		}
		time.Sleep(1 * time.Second)
	}
}
