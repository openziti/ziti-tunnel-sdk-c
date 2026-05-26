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
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// RequireConfigured skips the test when no IdP was configured (the test
// runner was invoked without -idp-bin). Safe to call on a nil receiver.
func (p *IdP) RequireConfigured(t *testing.T) {
	if p == nil {
		t.Skip("IdP is not configured (-idp-bin not provided)")
	}
}

// IdP is a running test identity provider used to exercise the OAuth2 PKCE flow.
type IdP struct {
	Bin            string
	WorkDir        string
	HTTPAddr       string
	IssuerURL      string
	ClientIDWorks  string
	ClientIDExtraA string
	ClientIDExtraB string
	Email          string
	Password       string
	ExternalID     string
	cmd            *exec.Cmd
}

type IdPUser struct {
	Email    string
	Username string
	UserID   string
	Password string
}

var DefaultIdPUser = IdPUser{
	Email:    "test@example.com",
	Username: "test",
	UserID:   "08a8684b-db88-4b73-90a9-3cd1661f5466",
	Password: "password",
}

// bcrypt of "password" at cost 10.
const defaultIdPBcryptHash = `$2a$10$2b2cU8CPhOTaGrs1HRQuAueS7JTT5ZHsHSzYiFPm1leZck7Mc8T4W`

// Start launches the IdP test binary against a generated config and waits
// for OIDC discovery. Caller must defer Stop(). The IdP's combined
// stdout+stderr is written to <WorkDir>/logs/idp.log so it sits alongside
// the zet logs and survives the test temp dir being deleted.
func (p *IdP) Start() error {
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

	p.ClientIDWorks = "ziti-test"
	p.ClientIDExtraA = "ziti-test-2"
	p.ClientIDExtraB = "ziti-test-3"

	clientsYAML := ""
	for _, id := range []string{p.ClientIDWorks, p.ClientIDExtraA, p.ClientIDExtraB} {
		clientsYAML += fmt.Sprintf(`  - id: %s
    redirectURIs:
      - http://127.0.0.1:20314/auth/callback
      - http://localhost:20314/auth/callback
    name: 'Ziti Test (%s)'
    public: true
`, id, id)
	}

	p.IssuerURL = issuer
	p.Email = DefaultIdPUser.Email
	p.Password = DefaultIdPUser.Password
	p.ExternalID = DefaultIdPUser.Email

	cfgPath := filepath.Join(p.WorkDir, "idp.yaml")
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
`, issuer, httpAddr, clientsYAML, DefaultIdPUser.Email, defaultIdPBcryptHash, DefaultIdPUser.Username, DefaultIdPUser.UserID)
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
	return p.IssuerURL + "/keys"
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
