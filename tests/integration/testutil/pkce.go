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
	"time"
)

// PKCE is a running test IdP used to exercise the OAuth2 PKCE flow.
type PKCE struct {
	Bin        string
	WorkDir    string
	HTTPAddr   string
	IssuerURL  string
	ClientIDs  []string
	Email      string
	Password   string
	ExternalID string
	cmd        *exec.Cmd
}

type PKCEUser struct {
	Email    string
	Username string
	UserID   string
	Password string
}

var DefaultPKCEUser = PKCEUser{
	Email:    "test@example.com",
	Username: "test",
	UserID:   "08a8684b-db88-4b73-90a9-3cd1661f5466",
	Password: "password",
}

// bcrypt of "password" at cost 10.
const defaultPKCEBcryptHash = `$2a$10$2b2cU8CPhOTaGrs1HRQuAueS7JTT5ZHsHSzYiFPm1leZck7Mc8T4W`

// StartPKCE launches the PKCE test IdP against a generated config and waits
// for OIDC discovery. Caller must defer Stop(). If logDir is non-empty, the
// IdP's combined stdout+stderr is written to <logDir>/pkce.log so it sits
// alongside the zet logs and survives the test temp dir being deleted.
func (p *PKCE) Start() error {
	if p.Bin == "" {
		return fmt.Errorf("PKCE binary path is empty")
	}
	if _, err := os.Stat(p.Bin); err != nil {
		return fmt.Errorf("PKCE binary not found: %w", err)
	}
	if err := os.MkdirAll(p.WorkDir, 0o755); err != nil {
		return fmt.Errorf("create PKCE work dir: %w", err)
	}

	port, err := pickFreePort()
	if err != nil {
		return fmt.Errorf("pick PKCE port: %w", err)
	}
	httpAddr := fmt.Sprintf("127.0.0.1:%d", port)
	issuer := "http://" + httpAddr + "/dex"

	clientIDs := []string{"ziti-test", "ziti-test-2", "ziti-test-3"}
	clientsYAML := ""
	for _, id := range clientIDs {
		clientsYAML += fmt.Sprintf(`  - id: %s
    redirectURIs:
      - http://127.0.0.1:20314/auth/callback
      - http://localhost:20314/auth/callback
    name: 'Ziti Test (%s)'
    public: true
`, id, id)
	}

	p.IssuerURL = issuer
	p.ClientIDs = clientIDs
	p.Email = DefaultPKCEUser.Email
	p.Password = DefaultPKCEUser.Password
	p.ExternalID = DefaultPKCEUser.Email

	cfgPath := filepath.Join(p.WorkDir, "pkce.yaml")
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
`, issuer, httpAddr, clientsYAML, DefaultPKCEUser.Email, defaultPKCEBcryptHash, DefaultPKCEUser.Username, DefaultPKCEUser.UserID)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		return fmt.Errorf("write PKCE config: %w", err)
	}

	logDir := filepath.Join(p.WorkDir, "logs")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return fmt.Errorf("failed to create PKCE log dir: %w", err)
	}
	logPath := filepath.Join(logDir, "pkce.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return fmt.Errorf("create PKCE log: %w", err)
	}

	p.cmd = exec.Command(p.Bin, "serve", cfgPath)
	p.cmd.Stdout = logFile
	p.cmd.Stderr = logFile
	if err := p.cmd.Start(); err != nil {
		logFile.Close()
		return fmt.Errorf("start PKCE: %w", err)
	}
	log.Printf("setup: started PKCE pid=%d issuer=%s log=%s", p.cmd.Process.Pid, issuer, logPath)

	if err := waitForPKCEDiscovery(issuer); err != nil {
		p.Stop()
		return fmt.Errorf("PKCE discovery never came up (see %s): %w", logPath, err)
	}
	return nil
}

func (p *PKCE) Stop() {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return
	}
	_ = p.cmd.Process.Kill()
	_, _ = p.cmd.Process.Wait()
	p.cmd = nil
}

func (p *PKCE) JWKSURI() string {
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

func waitForPKCEDiscovery(issuer string) error {
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
