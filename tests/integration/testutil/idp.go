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
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// RequireConfigured skips the test when no IdP was configured (the IdP block in
// the JSON config is missing the binary in test-harness mode, or the issuer in
// pre-existing-IdP mode). Safe to call on a nil receiver.
func (p *IdP) RequireConfigured(t *testing.T) {
	if p == nil || p.IssuerURL == "" {
		t.Skip("IdP is not configured (no issuer)")
	}
}

// IdP is a running test identity provider used to exercise the OAuth2 PKCE flow.
// When UseTestHarnessIdP is true, Start() spawns a local dex from Bin and seeds
// the User. When false, Start() assumes IssuerURL points at a pre-existing IdP
// that already has the User provisioned.
type IdP struct {
	UseTestHarnessIdP bool
	Bin               string
	WorkDir           string
	HTTPAddr          string
	IssuerURL         string
	JwksURI           string
	SignerName        string
	ClientIDWorks     string
	ClientIDExtraA    string
	ClientIDExtraB    string
	Audience          string
	Sub               string
	Scopes            string
	Email             string
	Password          string
	Username          string
	UserID            string
	ExternalID        string
	cmd               *exec.Cmd
}

type IdPUser struct {
	Email    string `json:"email"`
	Username string `json:"username"`
	UserID   string `json:"userID"`
	Password string `json:"password"`
}

// Start launches the IdP test binary against a generated config and waits
// for OIDC discovery (test-harness mode), or validates the configured external issuer
// (pre-existing-IdP mode). Caller must defer Stop(). In test-harness mode, the IdP's
// combined stdout+stderr is written to <WorkDir>/logs/idp.log so it sits
// alongside the zet logs and survives the test temp dir being deleted.
func (p *IdP) Start() error {
	if !p.UseTestHarnessIdP {
		if p.IssuerURL == "" {
			log.Printf("setup: IdP not configured (useTestHarnessIdP=false, no issuer); IdP-dependent tests will skip")
			return nil
		}
		log.Printf("setup: using pre-existing IdP issuer=%s", p.IssuerURL)
		jwks, err := fetchJWKSURI(p.IssuerURL)
		if err != nil {
			return fmt.Errorf("OIDC discovery for %s: %w", p.IssuerURL, err)
		}
		p.JwksURI = jwks
		log.Printf("setup: discovered jwks_uri=%s", jwks)
		return nil
	}

	if p.Bin == "" {
		return fmt.Errorf("IdP binary path is empty")
	}
	if _, err := os.Stat(p.Bin); err != nil {
		return fmt.Errorf("IdP binary not found: %w", err)
	}
	if err := os.MkdirAll(p.WorkDir, 0o755); err != nil {
		return fmt.Errorf("create IdP work dir: %w", err)
	}

	port, err := pickFreePort()
	if err != nil {
		return fmt.Errorf("pick IdP port: %w", err)
	}
	httpAddr := fmt.Sprintf("127.0.0.1:%d", port)
	issuer := "http://" + httpAddr + "/dex"

	clientsYAML := ""
	for _, id := range []string{p.ClientIDWorks, p.ClientIDExtraA, p.ClientIDExtraB} {
		if id == "" {
			continue
		}
		clientsYAML += fmt.Sprintf(`  - id: %s
    redirectURIs:
      - http://127.0.0.1:20314/auth/callback
      - http://localhost:20314/auth/callback
    name: 'Ziti Test (%s)'
    public: true
`, id, id)
	}

	p.IssuerURL = issuer
	p.HTTPAddr = httpAddr

	cfgPath := filepath.Join(p.WorkDir, "idp.yaml")
	const defaultIdPBcryptHash = `$2a$10$2b2cU8CPhOTaGrs1HRQuAueS7JTT5ZHsHSzYiFPm1leZck7Mc8T4W`
	cfg := fmt.Sprintf(`issuer: %s
storage:
  type: memory
web:
  http: %s
oauth2:
  skipApprovalScreen: true
staticClients:
%senablePasswordDB: true
staticPasswords:
  - email: %q
    hash: %q
    username: %q
    userID: %q
`, issuer, httpAddr, clientsYAML, p.Email, defaultIdPBcryptHash, p.Username, p.UserID)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		return fmt.Errorf("write IdP config: %w", err)
	}

	logDir := filepath.Join(p.WorkDir, "logs")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return fmt.Errorf("failed to create IdP log dir: %w", err)
	}
	logPath := filepath.Join(logDir, "idp.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return fmt.Errorf("create IdP log: %w", err)
	}

	p.cmd = exec.Command(p.Bin, "serve", cfgPath)
	p.cmd.Stdout = logFile
	p.cmd.Stderr = logFile
	if err := p.cmd.Start(); err != nil {
		logFile.Close()
		return fmt.Errorf("start IdP: %w", err)
	}
	log.Printf("setup: started IdP pid=%d issuer=%s log=%s", p.cmd.Process.Pid, issuer, logPath)

	if err := waitForIdPDiscovery(issuer); err != nil {
		p.Stop()
		return fmt.Errorf("IdP discovery never came up (see %s): %w", logPath, err)
	}
	jwks, err := fetchJWKSURI(issuer)
	if err != nil {
		p.Stop()
		return fmt.Errorf("OIDC discovery for %s: %w", issuer, err)
	}
	p.JwksURI = jwks
	return nil
}

func (p *IdP) Stop() {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return
	}
	_ = p.cmd.Process.Kill()
	_, _ = p.cmd.Process.Wait()
	p.cmd = nil
}

func (p *IdP) JWKSURI() string {
	return p.JwksURI
}

// fetchJWKSURI reads the IdP's OIDC discovery document and returns its jwks_uri.
// This is the standard endpoint across dex, keycloak, and auth0, so the signer
// gets the right JWKS URL without per-IdP conventions.
func fetchJWKSURI(issuer string) (string, error) {
	endpoint := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(endpoint)
	if err != nil {
		return "", fmt.Errorf("get %s: %w", endpoint, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("get %s: status %d", endpoint, resp.StatusCode)
	}
	var doc struct {
		JwksURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", fmt.Errorf("decode discovery %s: %w", endpoint, err)
	}
	if doc.JwksURI == "" {
		return "", fmt.Errorf("discovery %s has no jwks_uri", endpoint)
	}
	return doc.JwksURI, nil
}

func pickFreePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func waitForIdPDiscovery(issuer string) error {
	client := &http.Client{Timeout: 2 * time.Second}
	url := issuer + "/.well-known/openid-configuration"
	for {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
}
