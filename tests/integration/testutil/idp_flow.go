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
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// DriveIdPFlow acts as the browser in the IdP's OIDC password flow, logging in
// as email and following redirects from authURL through the login form back to
// ZET's loopback callback at localhost:20314.
func (p *IdP) DriveIdPFlow(t *testing.T, authUrl, email string) {
	t.Logf("driving IdP login flow (issuer=%s email=%s)", p.IssuerURL, email)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err, "create cookie jar")
	client := &http.Client{
		Timeout: 30 * time.Second,
		Jar:     jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	loginPageURL, err := followRedirectsTo200(client, authUrl, 8)
	require.NoError(t, err, "follow authorize redirects")

	req, err := http.NewRequest(http.MethodGet, loginPageURL, nil)
	require.NoError(t, err, "build login page request")
	resp, err := client.Do(req)
	require.NoError(t, err, "get login page")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "login page status=%d body=%s", resp.StatusCode, truncate(body, 200))

	formAction, form, err := parseLoginForm(string(body), email, p.Password)
	require.NoError(t, err, "parse IdP login form (body=%s)", truncate(body, 200))
	postURL, err := absoluteURL(loginPageURL, formAction)
	require.NoError(t, err, "resolve form action %q", formAction)
	req, err = http.NewRequest(http.MethodPost, postURL, strings.NewReader(form.Encode()))
	require.NoError(t, err, "build credentials POST")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err = client.Do(req)
	require.NoError(t, err, "post credentials")
	postBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Contains(t, []int{http.StatusSeeOther, http.StatusFound}, resp.StatusCode, "login POST status=%d body=%s", resp.StatusCode, truncate(postBody, 200))

	loc := resp.Header.Get("Location")
	require.NotEmpty(t, loc, "no Location after login POST")
	current, err := absoluteURL(postURL, loc)
	require.NoError(t, err, "resolve post-login location")

	for i := 0; i < 8; i++ {
		u, err := url.Parse(current)
		require.NoError(t, err, "parse next location %q", current)
		if isLoopbackCallback(u) {
			require.NoError(t, hitLoopback(client, current), "hit loopback callback")
			t.Logf("IdP login flow completed")
			return
		}
		req, err = http.NewRequest(http.MethodGet, current, nil)
		require.NoError(t, err, "build redirect-chain request")
		resp, err = client.Do(req)
		require.NoError(t, err, "GET %s", current)
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		require.Contains(t, []int{http.StatusSeeOther, http.StatusFound}, resp.StatusCode, "expected redirect chain, got status=%d at %s", resp.StatusCode, current)
		next := resp.Header.Get("Location")
		require.NotEmpty(t, next, "no Location at %s (status=%d)", current, resp.StatusCode)
		current, err = absoluteURL(current, next)
		require.NoError(t, err, "resolve next location")
	}
	require.Failf(t, "IdP login redirect chain did not finish", "did not reach loopback callback within hop limit (last=%s)", current)
}

func followRedirectsTo200(client *http.Client, start string, maxHops int) (string, error) {
	current := start
	for i := 0; i < maxHops; i++ {
		req, err := http.NewRequest(http.MethodGet, current, nil)
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

var (
	formRe  = regexp.MustCompile(`(?is)<form([^>]*)>(.*?)</form>`)
	inputRe = regexp.MustCompile(`(?is)<input\b([^>]*)>`)
	attrRe  = regexp.MustCompile(`(?is)([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)')`)
)

// parseLoginForm finds the IdP login form (the <form> that holds a password
// input), carries forward every input it declares, and fills the detected
// username and password fields. Reading the form instead of hardcoding field
// names keeps the flow IdP-agnostic: dex uses login/password, keycloak and
// auth0 use username/password plus hidden state/CSRF fields, all handled here.
func parseLoginForm(body, email, password string) (string, url.Values, error) {
	for _, f := range formRe.FindAllStringSubmatch(body, -1) {
		formAttrs, inner := parseTagAttributes(f[1]), f[2]
		form := url.Values{}
		var passField, userField string
		for _, in := range inputRe.FindAllStringSubmatch(inner, -1) {
			a := parseTagAttributes(in[1])
			name := a["name"]
			if name == "" {
				continue
			}
			// Inputs are HTML-escaped, so hidden state like `?back=&state=x` is
			// rendered `&amp;`. Without decoding, the POST parses keys wrong and
			// the IdP returns 400.
			form.Set(name, html.UnescapeString(a["value"]))
			switch strings.ToLower(a["type"]) {
			case "password":
				passField = name
			case "", "text", "email", "tel":
				if userField == "" {
					userField = name
				}
			}
		}
		if passField == "" {
			continue
		}
		form.Set(passField, password)
		if userField != "" {
			form.Set(userField, email)
		}
		return html.UnescapeString(formAttrs["action"]), form, nil
	}
	return "", nil, fmt.Errorf("no login form with a password field found")
}

// parseTagAttributes parses an HTML tag's attributes into a lowercase-keyed map.
func parseTagAttributes(tag string) map[string]string {
	out := map[string]string{}
	for _, m := range attrRe.FindAllStringSubmatch(tag, -1) {
		value := m[2]
		if value == "" {
			value = m[3]
		}
		out[strings.ToLower(m[1])] = value
	}
	return out
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

func hitLoopback(client *http.Client, loopback string) error {
	// ZET's loopback can take a moment to bind after returning the auth URL.
	deadline := time.Now().Add(5 * time.Second)
	for {
		req, err := http.NewRequest(http.MethodGet, loopback, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("hit loopback: %w", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func truncate(b []byte, n int) string {
	s := string(b)
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
