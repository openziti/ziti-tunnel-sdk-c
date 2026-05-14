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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	adminUsername    = "admin"
	adminPassword    = "admin"
	overlayCtrlPort  = 1280
	overlayRtrPort   = 3022
)

type Overlay struct {
	ZitiBin        string
	Home           string
	ControllerPort uint16
	RouterPort     uint16
	ZitiMajor      int
	ZitiMinor      int

	extCmd  *exec.Cmd
	stdout  *syncBuffer
	stderr  *syncBuffer
	cmdDone chan error
}

// StartOverlay runs `ziti edge quickstart` with ephemeral ports in a temp home,
// waits for the controller to accept an admin login, and returns a handle.
// Callers must defer Stop().
func StartOverlay(ctx context.Context, zitiBin, home string) (*Overlay, error) {
	log.Printf("overlay: mkdir home %s", home)
	if err := os.MkdirAll(home, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir home: %w", err)
	}
	log.Printf("overlay: wiping previous DB state under %s", home)
	if err := wipeOverlayDB(home); err != nil {
		return nil, fmt.Errorf("wipe overlay db: %w", err)
	}

	args := []string{
		"edge", "quickstart",
		"--home=" + home,
		"--ctrl-address=localhost",
		fmt.Sprintf("--ctrl-port=%d", overlayCtrlPort),
		"--router-address=localhost",
		fmt.Sprintf("--router-port=%d", overlayRtrPort),
	}
	log.Printf("overlay: starting %s %s", zitiBin, strings.Join(args, " "))
	cmd := exec.CommandContext(ctx, zitiBin, args...)
	cmd.Env = append(os.Environ(),
		"ZITI_CONFIG_DIR="+filepath.Join(home, "cli-config"),
		"PFXLOG_NO_JSON=true",
	)
	stdout := newSyncBuffer()
	stderr := newSyncBuffer()
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start quickstart: %w", err)
	}

	o := &Overlay{
		ZitiBin:        zitiBin,
		Home:           home,
		ControllerPort: overlayCtrlPort,
		RouterPort:     overlayRtrPort,
		extCmd:         cmd,
		stdout:         stdout,
		stderr:         stderr,
		cmdDone:        make(chan error, 1),
	}
	go func() { o.cmdDone <- cmd.Wait() }()

	readyCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if err := o.waitUntilReady(readyCtx); err != nil {
		o.Stop()
		return nil, fmt.Errorf("overlay not ready: %w\n%s", err, o.Logs())
	}

	log.Printf("overlay: probing ziti version")
	major, minor, err := probeZitiVersion(ctx, zitiBin)
	if err != nil {
		o.Stop()
		return nil, fmt.Errorf("probe ziti version: %w", err)
	}
	o.ZitiMajor = major
	o.ZitiMinor = minor
	log.Printf("overlay: ready (ziti v%d.%d)", major, minor)
	return o, nil
}

// wipeOverlayDB removes per-instance state so quickstart re-seeds a clean
// controller DB, while keeping pki/root-ca intact so the OS trust install
// from a prior run remains valid. The intermediate CA bundle is signed by
// the same root and gets regenerated.
func wipeOverlayDB(home string) error {
	for _, p := range []string{
		filepath.Join(home, "instance-1"),
		filepath.Join(home, "pki", "intermediate-ca-instance-1"),
		filepath.Join(home, "pki", "root-ca", "certs", "intermediate-ca-instance-1.cert"),
		filepath.Join(home, "pki", "root-ca", "keys", "intermediate-ca-instance-1.key"),
	} {
		if err := os.RemoveAll(p); err != nil {
			return fmt.Errorf("remove %s: %w", p, err)
		}
	}
	return nil
}

func probeZitiVersion(ctx context.Context, zitiBin string) (int, int, error) {
	out, err := exec.CommandContext(ctx, zitiBin, "--version").Output()
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
	return fmt.Sprintf("https://localhost:%d", o.ControllerPort)
}

// RequireCATrusted skips the test (with OS-specific install/cleanup
// instructions) if the overlay's CA isn't in the calling OS's trust store.
func (o *Overlay) RequireCATrusted(t *testing.T) {
	t.Helper()
	hostport := fmt.Sprintf("localhost:%d", o.ControllerPort)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", hostport, nil)
	if err == nil {
		_ = conn.Close()
		return
	}
	caPath := filepath.Join(o.Home, "pki", "root-ca", "certs", "root-ca.cert")
	var install, cleanup string
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
	default:
		t.Skipf(`tests need the CA at %s in OS trust (no install instructions for %s).

  Current -overlay-home: %s
  Pass a durable path with -overlay-home so the PKI (and this trust install) persists across runs.`, caPath, runtime.GOOS, o.Home)
		return
	}
	t.Skipf(`tests need the test overlay's CA in OS trust.

  Current -overlay-home: %s
  Pass a durable path with -overlay-home so the PKI (and this trust install) persists across runs.

  Install:
  %s

  Cleanup when done:
  %s`, o.Home, install, cleanup)
}

// CACleanupCommand returns the OS-specific shell command a developer can run
// to remove this overlay's root CA from their OS trust store after testing.
func (o *Overlay) CACleanupCommand() string {
	caPath := filepath.Join(o.Home, "pki", "root-ca", "certs", "root-ca.cert")
	switch runtime.GOOS {
	case "windows":
		return fmt.Sprintf(`$c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 "%s"; Get-ChildItem Cert:\LocalMachine\Root | ? Thumbprint -eq $c.Thumbprint | Remove-Item`, caPath)
	case "darwin":
		return fmt.Sprintf(`sudo security delete-certificate -Z $(openssl x509 -in %s -noout -fingerprint -sha1 | sed 's/.*=//' | tr -d ':') /Library/Keychains/System.keychain`, caPath)
	case "linux":
		return `sudo rm /usr/local/share/ca-certificates/ziti-test.crt && sudo update-ca-certificates --fresh`
	}
	return ""
}

func (o *Overlay) Stop() {
	if o.extCmd.Process == nil {
		return
	}
	_ = o.extCmd.Process.Kill()
	select {
	case <-o.cmdDone:
	case <-time.After(10 * time.Second):
	}
}

func (o *Overlay) Logs() string {
	return fmt.Sprintf("--- ziti stdout ---\n%s\n--- ziti stderr ---\n%s",
		o.stdout.String(), o.stderr.String())
}

// CreateIdentityJWT provisions a new (non-admin) identity and returns its enrollment JWT content.
func (o *Overlay) CreateIdentityJWT(ctx context.Context, name string) (string, error) {
	jwtPath := filepath.Join(o.Home, name+".jwt")
	if _, err := o.runZiti(ctx, "edge", "create", "identity", name, "-o", jwtPath); err != nil {
		return "", fmt.Errorf("create identity %s: %w", name, err)
	}
	content, err := os.ReadFile(jwtPath)
	if err != nil {
		return "", fmt.Errorf("read jwt %s: %w", jwtPath, err)
	}
	return string(bytes.TrimSpace(content)), nil
}

func (o *Overlay) DeleteIdentity(ctx context.Context, name string) error {
	if _, err := o.runZiti(ctx, "edge", "delete", "identity", name); err != nil {
		return fmt.Errorf("delete identity %s: %w", name, err)
	}
	return nil
}

func (o *Overlay) CreateAuthPolicyRequiringTOTP(ctx context.Context, name string) error {
	if _, err := o.runZiti(ctx, "edge", "create", "auth-policy", name,
		"--primary-cert-allowed",
		"--secondary-req-totp"); err != nil {
		return fmt.Errorf("create auth policy %s: %w", name, err)
	}
	return nil
}

func (o *Overlay) CreateIdentityJWTWithAuthPolicy(ctx context.Context, name, authPolicy string) (string, error) {
	jwtPath := filepath.Join(o.Home, name+".jwt")
	if _, err := o.runZiti(ctx, "edge", "create", "identity", name,
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

// CreateExtJwtSigner registers an external JWT signer on the controller and
// returns its assigned ID. jwksEndpoint is the URL the controller fetches
// public keys from to verify incoming JWTs; externalAuthURL is what the SDK
// directs users to so they can obtain a JWT (the IdP's /authorize equivalent).
func (o *Overlay) CreateExtJwtSigner(ctx context.Context, name, issuer, jwksEndpoint, audience, clientID, externalAuthURL string) (string, error) {
	return o.CreateExtJwtSignerWithClaim(ctx, name, issuer, jwksEndpoint, audience, clientID, externalAuthURL, "")
}

// CreateExtJwtSignerWithClaim is CreateExtJwtSigner with control over which
// JWT claim the controller maps to identity externalId. Empty claimsProperty
// defers to the controller default ("sub").
func (o *Overlay) CreateExtJwtSignerWithClaim(ctx context.Context, name, issuer, jwksEndpoint, audience, clientID, externalAuthURL, claimsProperty string) (string, error) {
	args := []string{"edge", "create", "ext-jwt-signer", name, issuer,
		"--jwks-endpoint", jwksEndpoint,
		"--audience", audience,
		"--client-id", clientID,
		"--external-auth-url", externalAuthURL,
	}
	if claimsProperty != "" {
		args = append(args, "--claims-property", claimsProperty)
	}
	out, err := o.runZiti(ctx, args...)
	if err != nil {
		return "", fmt.Errorf("create ext-jwt-signer %s: %w", name, err)
	}
	return string(bytes.TrimSpace(out)), nil
}

// CreateAuthPolicyForExtJwt creates an auth policy whose primary auth method
// is the ext-jwt-signer set with the given IDs. Pass one or more signer IDs.
func (o *Overlay) CreateAuthPolicyForExtJwt(ctx context.Context, name string, signerIDs ...string) error {
	args := []string{"edge", "create", "auth-policy", name, "--primary-ext-jwt-allowed"}
	for _, id := range signerIDs {
		args = append(args, "--primary-ext-jwt-allowed-signers", id)
	}
	if _, err := o.runZiti(ctx, args...); err != nil {
		return fmt.Errorf("create auth policy %s: %w", name, err)
	}
	return nil
}

// CreateIdentityWithExternalId provisions a non-admin identity bound to the
// named auth policy and stamped with externalId so the controller can match it
// against the "sub" claim of an ext-jwt-signer-issued JWT.
func (o *Overlay) CreateIdentityWithExternalId(ctx context.Context, name, externalID, authPolicy string) error {
	if _, err := o.runZiti(ctx, "edge", "create", "identity", name,
		"--external-id", externalID,
		"-P", authPolicy,
	); err != nil {
		return fmt.Errorf("create identity %s with externalId %s: %w", name, externalID, err)
	}
	return nil
}

// CreateUpdbUser creates a non-admin identity with a UPDB authenticator so the
// identity can authenticate via the controller's built-in OIDC username/password
// login. Returns the new identity's controller ID.
func (o *Overlay) CreateUpdbUser(ctx context.Context, name, username, password string) (string, error) {
	out, err := o.runZiti(ctx, "edge", "create", "identity", name, "-j")
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
	if _, err := o.runZiti(ctx, "edge", "create", "authenticator", "updb", resp.Data.ID, username, password); err != nil {
		return "", fmt.Errorf("create updb authenticator for %s: %w", name, err)
	}
	return resp.Data.ID, nil
}

// DeleteExtJwtSigner removes an ext-jwt-signer by name.
func (o *Overlay) DeleteExtJwtSigner(ctx context.Context, name string) error {
	if _, err := o.runZiti(ctx, "edge", "delete", "ext-jwt-signer", name); err != nil {
		return fmt.Errorf("delete ext-jwt-signer %s: %w", name, err)
	}
	return nil
}

// DeleteAuthPolicy removes an auth policy by name.
func (o *Overlay) DeleteAuthPolicy(ctx context.Context, name string) error {
	if _, err := o.runZiti(ctx, "edge", "delete", "auth-policy", name); err != nil {
		return fmt.Errorf("delete auth policy %s: %w", name, err)
	}
	return nil
}

// CreateHostConfigV1 creates a host.v1 config that forwards to forwardAddr:forwardPort.
func (o *Overlay) CreateHostConfigV1(ctx context.Context, name, protocol, forwardAddr string, forwardPort int) error {
	body, err := json.Marshal(struct {
		Protocol string `json:"protocol"`
		Address  string `json:"address"`
		Port     int    `json:"port"`
	}{Protocol: protocol, Address: forwardAddr, Port: forwardPort})
	if err != nil {
		return err
	}
	if _, err := o.runZiti(ctx, "edge", "create", "config", name, "host.v1", string(body)); err != nil {
		return fmt.Errorf("create host config %s: %w", name, err)
	}
	return nil
}

// CreateInterceptConfigV1 creates an intercept.v1 config matching the given protocols, addresses, and port range.
func (o *Overlay) CreateInterceptConfigV1(ctx context.Context, name string, protocols, addresses []string, portLow, portHigh int) error {
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
	if _, err := o.runZiti(ctx, "edge", "create", "config", name, "intercept.v1", string(body)); err != nil {
		return fmt.Errorf("create intercept config %s: %w", name, err)
	}
	return nil
}

// CreateService creates a service that references the given configs.
func (o *Overlay) CreateService(ctx context.Context, name string, configs []string) error {
	args := []string{"edge", "create", "service", name, "--configs", strings.Join(configs, ",")}
	if _, err := o.runZiti(ctx, args...); err != nil {
		return fmt.Errorf("create service %s: %w", name, err)
	}
	return nil
}

// CreateBindServicePolicy creates a Bind service policy granting identityName access to serviceName.
func (o *Overlay) CreateBindServicePolicy(ctx context.Context, name, identityName, serviceName string) error {
	if _, err := o.runZiti(ctx, "edge", "create", "service-policy", name, "Bind",
		"--identity-roles", "@"+identityName,
		"--service-roles", "@"+serviceName,
		"--semantic", "AnyOf",
	); err != nil {
		return fmt.Errorf("create bind policy %s: %w", name, err)
	}
	return nil
}

// CreateDialServicePolicy creates a Dial service policy granting identityName access to serviceName.
func (o *Overlay) CreateDialServicePolicy(ctx context.Context, name, identityName, serviceName string) error {
	if _, err := o.runZiti(ctx, "edge", "create", "service-policy", name, "Dial",
		"--identity-roles", "@"+identityName,
		"--service-roles", "@"+serviceName,
		"--semantic", "AnyOf",
	); err != nil {
		return fmt.Errorf("create dial policy %s: %w", name, err)
	}
	return nil
}

// DeleteServicePolicy deletes a service policy by name.
func (o *Overlay) DeleteServicePolicy(ctx context.Context, name string) error {
	if _, err := o.runZiti(ctx, "edge", "delete", "service-policy", name); err != nil {
		return fmt.Errorf("delete service policy %s: %w", name, err)
	}
	return nil
}

// DeleteService deletes a service by name.
func (o *Overlay) DeleteService(ctx context.Context, name string) error {
	if _, err := o.runZiti(ctx, "edge", "delete", "service", name); err != nil {
		return fmt.Errorf("delete service %s: %w", name, err)
	}
	return nil
}

// DeleteConfig deletes a config by name.
func (o *Overlay) DeleteConfig(ctx context.Context, name string) error {
	if _, err := o.runZiti(ctx, "edge", "delete", "config", name); err != nil {
		return fmt.Errorf("delete config %s: %w", name, err)
	}
	return nil
}

func (o *Overlay) waitUntilReady(ctx context.Context) error {
	if err := o.waitForControllerPort(ctx); err != nil {
		return err
	}
	log.Printf("overlay: attempting admin login at %s", o.ControllerHostPort())
	var lastErr error
	for {
		if _, err := o.runZiti(ctx, "edge", "login", o.ControllerHostPort(),
			"-u", adminUsername, "-p", adminPassword, "--yes"); err == nil {
			log.Printf("overlay: admin login OK")
			return nil
		} else {
			lastErr = err
		}
		select {
		case err := <-o.cmdDone:
			return fmt.Errorf("quickstart exited before becoming ready: %v", err)
		case <-ctx.Done():
			return fmt.Errorf("%w (last login error: %v)", ctx.Err(), lastErr)
		case <-time.After(1 * time.Second):
		}
	}
}

func (o *Overlay) waitForControllerPort(ctx context.Context) error {
	addr := fmt.Sprintf("localhost:%d", o.ControllerPort)
	log.Printf("overlay: waiting for controller TCP port %s", addr)
	var lastErr error
	for {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			_ = conn.Close()
			log.Printf("overlay: controller port %s open", addr)
			return nil
		}
		lastErr = err
		select {
		case exitErr := <-o.cmdDone:
			return fmt.Errorf("quickstart exited before port %d opened: %v", o.ControllerPort, exitErr)
		case <-ctx.Done():
			return fmt.Errorf("%w (last dial error: %v)", ctx.Err(), lastErr)
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// runZiti invokes the ziti CLI with ZITI_CONFIG_DIR pointed at the overlay's
// session cache, so logins performed during readiness polling carry through.
func (o *Overlay) runZiti(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, o.ZitiBin, args...)
	cmd.Env = append(os.Environ(),
		"ZITI_HOME="+o.Home,
		"ZITI_CONFIG_DIR="+filepath.Join(o.Home, "cli-config"),
	)
	var stdout, stderr syncBuffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s %v: %w\nstdout: %s\nstderr: %s",
			o.ZitiBin, args, err, stdout.String(), stderr.String())
	}
	return []byte(stdout.String()), nil
}

// PurgeIdentities deletes every identity whose name contains prefix.
func (o *Overlay) PurgeIdentities(ctx context.Context, prefix string) error {
	return o.deleteWhere(ctx, "identities", prefix)
}

// PurgeAuthPolicies deletes every auth policy whose name contains prefix.
func (o *Overlay) PurgeAuthPolicies(ctx context.Context, prefix string) error {
	return o.deleteWhere(ctx, "auth-policies", prefix)
}

// PurgeExtJwtSigners deletes every ext-jwt-signer whose name contains prefix.
func (o *Overlay) PurgeExtJwtSigners(ctx context.Context, prefix string) error {
	return o.deleteWhere(ctx, "ext-jwt-signers", prefix)
}

func (o *Overlay) deleteWhere(ctx context.Context, entity, prefix string) error {
	filter := fmt.Sprintf(`name contains "%s" limit none`, prefix)
	if _, err := o.runZiti(ctx, "edge", "delete", entity, "where", filter); err != nil {
		return fmt.Errorf("delete %s where %s: %w", entity, filter, err)
	}
	return nil
}
