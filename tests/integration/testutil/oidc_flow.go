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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DiscoverOIDCJWKS fetches <issuerBase>/.well-known/openid-configuration and
// returns the jwks_uri the provider advertises.
func DiscoverOIDCJWKS(ctx context.Context, issuerBase string) (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, issuerBase+"/.well-known/openid-configuration", nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("discovery status=%d", resp.StatusCode)
	}
	var doc struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", fmt.Errorf("parse discovery: %w", err)
	}
	if doc.JWKSURI == "" {
		return "", fmt.Errorf("discovery missing jwks_uri")
	}
	return doc.JWKSURI, nil
}

// DriveControllerOIDC walks the controller's built-in OIDC login flow against
// the authorize URL ZET hands back from ExternalAuth: GET /oidc/authorize,
// POST /oidc/login/username, then GET /oidc/authorize/callback, whose 302
// sends the code into ZET's loopback listener at localhost:20314.
func DriveControllerOIDC(ctx context.Context, authURL, controllerBaseURL, username, password string) error {
	client := &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("get authorize: %w", err)
	}
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	authRequestID := loc.Query().Get("authRequestID")
	if authRequestID == "" {
		return fmt.Errorf("authRequestID missing from authorize response (status=%d location=%q)",
			resp.StatusCode, resp.Header.Get("Location"))
	}

	form := url.Values{"id": {authRequestID}, "username": {username}, "password": {password}}
	req, err = http.NewRequestWithContext(ctx, http.MethodPost,
		controllerBaseURL+"/oidc/login/username", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err = client.Do(req)
	if err != nil {
		return fmt.Errorf("post login: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("login status=%d", resp.StatusCode)
	}

	req, err = http.NewRequestWithContext(ctx, http.MethodGet,
		controllerBaseURL+"/oidc/authorize/callback?id="+url.QueryEscape(authRequestID), nil)
	if err != nil {
		return err
	}
	resp, err = client.Do(req)
	if err != nil {
		return fmt.Errorf("get callback: %w", err)
	}
	resp.Body.Close()
	loopback := resp.Header.Get("Location")
	if loopback == "" {
		return fmt.Errorf("loopback URL missing from callback response (status=%d)", resp.StatusCode)
	}

	// ziti-sdk-c can return the auth URL before localhost:20314 is reachable; retry.
	loopCtx, loopCancel := context.WithTimeout(ctx, 5*time.Second)
	defer loopCancel()
	for {
		req, err = http.NewRequestWithContext(loopCtx, http.MethodGet, loopback, nil)
		if err != nil {
			return err
		}
		resp, err = client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			return nil
		}
		select {
		case <-loopCtx.Done():
			return fmt.Errorf("hit loopback: %w (last: %v)", loopCtx.Err(), err)
		case <-time.After(100 * time.Millisecond):
		}
	}
}
