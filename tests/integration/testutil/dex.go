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

// Dex is a running instance of the Dex OIDC provider, used as a test IdP.
// The static config below provisions one client ("ziti-test") and one user
// (test@example.com / password), backed by in-memory storage.
type Dex struct {
	Bin       string
	WorkDir   string
	HTTPAddr  string // host:port (e.g. 127.0.0.1:5556)
	IssuerURL string // <httpAddr>/dex
	// ClientIDs registered as staticClients in dex. The primary client is the
	// first entry; additional entries exist so the multi-signer test can pin
	// each ext-jwt-signer to a distinct audience.
	ClientIDs []string
	Email     string // login identifier dex's password connector expects
	Password  string
	ExternalID string // value of the email claim that ext-jwt-signer will map to identity externalId
	cmd        *exec.Cmd
}

// DexUser describes the single static user provisioned in the test IdP.
type DexUser struct {
	Email    string
	Username string
	UserID   string
	Password string
}

// DefaultDexUser is the canned account used by tests.
//
// hash is bcrypt(password) with cost 10. Pre-computed so tests don't pay
// the bcrypt cost at startup. The plaintext is "password".
var DefaultDexUser = DexUser{
	Email:    "test@example.com",
	Username: "test",
	UserID:   "08a8684b-db88-4b73-90a9-3cd1661f5466",
	Password: "password",
}

const defaultDexBcryptHash = `$2a$10$2b2cU8CPhOTaGrs1HRQuAueS7JTT5ZHsHSzYiFPm1leZck7Mc8T4W`

// StartDex writes a config file to workDir, picks a free port, launches the
// dex binary against it, and waits for the discovery endpoint to respond.
// Caller must defer Stop().
func StartDex(ctx context.Context, dexBin, workDir string) (*Dex, error) {
	if dexBin == "" {
		return nil, fmt.Errorf("dex binary path is empty")
	}
	if _, err := os.Stat(dexBin); err != nil {
		return nil, fmt.Errorf("dex binary not found: %w", err)
	}
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return nil, fmt.Errorf("create dex work dir: %w", err)
	}

	port, err := pickFreePort()
	if err != nil {
		return nil, fmt.Errorf("pick dex port: %w", err)
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

	cfgPath := filepath.Join(workDir, "dex.yaml")
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
`, issuer, httpAddr, clientsYAML, DefaultDexUser.Email, defaultDexBcryptHash, DefaultDexUser.Username, DefaultDexUser.UserID)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		return nil, fmt.Errorf("write dex config: %w", err)
	}

	logPath := filepath.Join(workDir, "dex.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return nil, fmt.Errorf("create dex log: %w", err)
	}

	cmd := exec.CommandContext(ctx, dexBin, "serve", cfgPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		logFile.Close()
		return nil, fmt.Errorf("start dex: %w", err)
	}
	log.Printf("setup: started dex pid=%d issuer=%s log=%s", cmd.Process.Pid, issuer, logPath)

	d := &Dex{
		Bin:       dexBin,
		WorkDir:   workDir,
		HTTPAddr:  httpAddr,
		IssuerURL: issuer,
		ClientIDs:  clientIDs,
		Email:      DefaultDexUser.Email,
		Password:   DefaultDexUser.Password,
		ExternalID: DefaultDexUser.Email,
		cmd:        cmd,
	}

	if err := waitForDexDiscovery(ctx, issuer, 15*time.Second); err != nil {
		d.Stop()
		return nil, fmt.Errorf("dex discovery never came up (see %s): %w", logPath, err)
	}
	return d, nil
}

// Stop kills the dex process. Safe to call multiple times.
func (d *Dex) Stop() {
	if d == nil || d.cmd == nil || d.cmd.Process == nil {
		return
	}
	_ = d.cmd.Process.Kill()
	_, _ = d.cmd.Process.Wait()
	d.cmd = nil
}

// JWKSURI returns the JWKS endpoint that dex advertises.
func (d *Dex) JWKSURI() string {
	return d.IssuerURL + "/keys"
}

func pickFreePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func waitForDexDiscovery(ctx context.Context, issuer string, timeout time.Duration) error {
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
