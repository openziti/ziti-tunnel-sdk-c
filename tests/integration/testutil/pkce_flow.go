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
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// DrivePKCEFlow acts as the browser in the IdP's OIDC password flow, following
// redirects from authURL through the login form back to ZET's loopback
// callback at localhost:20314.
func DrivePKCEFlow(ctx context.Context, authURL, issuer, username, password string) error {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return fmt.Errorf("create cookie jar: %w", err)
	}
	client := &http.Client{
		Timeout: 30 * time.Second,
		Jar:     jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// 1. follow authorize redirects to the login page
	loginPageURL, err := followRedirectsTo200(ctx, client, authURL, 8)
	if err != nil {
		return fmt.Errorf("follow authorize redirects: %w", err)
	}

	// 2. fetch login page, extract form action
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, loginPageURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("get login page: %w", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("login page status=%d body=%s", resp.StatusCode, truncate(body, 200))
	}

	formAction, err := extractFormAction(string(body))
	if err != nil {
		return fmt.Errorf("parse PKCE login form: %w (body=%s)", err, truncate(body, 200))
	}
	postURL, err := absoluteURL(loginPageURL, formAction)
	if err != nil {
		return fmt.Errorf("resolve form action %q: %w", formAction, err)
	}

	// 3. post credentials
	form := url.Values{
		"login":    {username},
		"password": {password},
	}
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, postURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err = client.Do(req)
	if err != nil {
		return fmt.Errorf("post credentials: %w", err)
	}
	postBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther && resp.StatusCode != http.StatusFound {
		return fmt.Errorf("login POST status=%d body=%s", resp.StatusCode, truncate(postBody, 200))
	}

	// 4. follow the callback chain until we hit ZET's loopback
	loc := resp.Header.Get("Location")
	if loc == "" {
		return fmt.Errorf("no Location after login POST")
	}
	current, err := absoluteURL(postURL, loc)
	if err != nil {
		return fmt.Errorf("resolve post-login location: %w", err)
	}

	for i := 0; i < 8; i++ {
		u, err := url.Parse(current)
		if err != nil {
			return fmt.Errorf("parse next location %q: %w", current, err)
		}
		if isLoopbackCallback(u) {
			return hitLoopback(ctx, client, current)
		}
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, current, nil)
		if err != nil {
			return err
		}
		resp, err = client.Do(req)
		if err != nil {
			return fmt.Errorf("GET %s: %w", current, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusSeeOther && resp.StatusCode != http.StatusFound {
			return fmt.Errorf("expected redirect chain, got status=%d at %s", resp.StatusCode, current)
		}
		next := resp.Header.Get("Location")
		if next == "" {
			return fmt.Errorf("no Location at %s (status=%d)", current, resp.StatusCode)
		}
		current, err = absoluteURL(current, next)
		if err != nil {
			return fmt.Errorf("resolve next location: %w", err)
		}
	}
	return fmt.Errorf("did not reach loopback callback within hop limit (last=%s)", current)
}

func followRedirectsTo200(ctx context.Context, client *http.Client, start string, maxHops int) (string, error) {
	current := start
	for i := 0; i < maxHops; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, current, nil)
		if err != nil {
			return "", err
		}
		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			return current, nil
		}
		loc := resp.Header.Get("Location")
		if loc == "" {
			return "", fmt.Errorf("redirect with no Location at %s (status=%d)", current, resp.StatusCode)
		}
		current, err = absoluteURL(current, loc)
		if err != nil {
			return "", err
		}
	}
	return "", fmt.Errorf("too many redirects starting at %s", start)
}

var formActionRe = regexp.MustCompile(`(?is)<form[^>]*\saction="([^"]+)"`)

func extractFormAction(body string) (string, error) {
	m := formActionRe.FindStringSubmatch(body)
	if len(m) < 2 {
		return "", fmt.Errorf("no <form action=...> in body")
	}
	// The IdP HTML-escapes the action attribute, so `?back=&state=<id>` is
	// rendered as `?back=&amp;state=<id>`. Without decoding, the POSTed query
	// parses as keys `back` and `amp;state`, and login returns 400.
	return html.UnescapeString(m[1]), nil
}

func absoluteURL(base, ref string) (string, error) {
	b, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	r, err := url.Parse(ref)
	if err != nil {
		return "", err
	}
	return b.ResolveReference(r).String(), nil
}

func isLoopbackCallback(u *url.URL) bool {
	if u.Path != "/auth/callback" {
		return false
	}
	host := u.Hostname()
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func hitLoopback(ctx context.Context, client *http.Client, loopback string) error {
	// ZET's loopback can take a moment to bind after returning the auth URL.
	loopCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		req, err := http.NewRequestWithContext(loopCtx, http.MethodGet, loopback, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
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

func truncate(b []byte, n int) string {
	s := string(b)
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
