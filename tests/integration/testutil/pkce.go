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
func StartPKCE(ctx context.Context, pkceBin, workDir, logDir string) (*PKCE, error) {
	if pkceBin == "" {
		return nil, fmt.Errorf("PKCE binary path is empty")
	}
	if _, err := os.Stat(pkceBin); err != nil {
		return nil, fmt.Errorf("PKCE binary not found: %w", err)
	}
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return nil, fmt.Errorf("create PKCE work dir: %w", err)
	}

	port, err := pickFreePort()
	if err != nil {
		return nil, fmt.Errorf("pick PKCE port: %w", err)
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

	cfgPath := filepath.Join(workDir, "pkce.yaml")
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
		return nil, fmt.Errorf("write PKCE config: %w", err)
	}

	logDest := workDir
	if logDir != "" {
		if err := os.MkdirAll(logDir, 0o755); err != nil {
			return nil, fmt.Errorf("create PKCE log dir: %w", err)
		}
		logDest = logDir
	}
	logPath := filepath.Join(logDest, "pkce.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return nil, fmt.Errorf("create PKCE log: %w", err)
	}

	cmd := exec.CommandContext(ctx, pkceBin, "serve", cfgPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		logFile.Close()
		return nil, fmt.Errorf("start PKCE: %w", err)
	}
	log.Printf("setup: started PKCE pid=%d issuer=%s log=%s", cmd.Process.Pid, issuer, logPath)

	p := &PKCE{
		Bin:        pkceBin,
		WorkDir:    workDir,
		HTTPAddr:   httpAddr,
		IssuerURL:  issuer,
		ClientIDs:  clientIDs,
		Email:      DefaultPKCEUser.Email,
		Password:   DefaultPKCEUser.Password,
		ExternalID: DefaultPKCEUser.Email,
		cmd:        cmd,
	}

	if err := waitForPKCEDiscovery(ctx, issuer, 15*time.Second); err != nil {
		p.Stop()
		return nil, fmt.Errorf("PKCE discovery never came up (see %s): %w", logPath, err)
	}
	return p, nil
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

func waitForPKCEDiscovery(ctx context.Context, issuer string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 2 * time.Second}
	url := issuer + "/.well-known/openid-configuration"
	var lastErr error
	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(150 * time.Millisecond):
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("timeout")
	}
	return lastErr
}
