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
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// IdentityName returns a filesystem-safe identity filename derived from
// t.Name(). Subtests produce names like "TestX/sub"; ZET rejects the slash
// in AddIdentity filenames, so it is replaced.
func IdentityName(t *testing.T) string {
	return strings.ReplaceAll(t.Name(), "/", "-")
}

type IdentityFileContent struct {
	ZtAPI  string   `json:"ztAPI"`
	ZtAPIs []string `json:"ztAPIs"`
	ID     struct {
		Cert string `json:"cert"`
		Key  string `json:"key"`
		CA   string `json:"ca"`
	} `json:"id"`
}

func ReadIdentityFile(t *testing.T, path string) IdentityFileContent {
	// ZET rewrites the identity file right after each connect, so a read can
	// land mid-rewrite and fail transiently
	raw, err := os.ReadFile(path)
	for attempts := 0; err != nil && attempts < 100; attempts++ {
		time.Sleep(10 * time.Millisecond)
		raw, err = os.ReadFile(path)
	}
	require.NoError(t, err, "failed to read identity file at %s", path)

	var content IdentityFileContent
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	require.NoError(t, dec.Decode(&content), "identity file at %s has unknown fields or invalid shape: %s", path, raw)
	return content
}

// RedirectIdentityFile rewrites ZtAPI/ZtAPIs in the identity file at path so
// every entry points at addr instead of the real controller, preserving each
// URL's original scheme and path. Shared by tests that need a running ZET to
// dial a controllable stand-in (a dead controller, an outage proxy) instead
// of the real address it enrolled against.
func RedirectIdentityFile(t *testing.T, path, addr string) {
	t.Helper()
	content := ReadIdentityFile(t, path)

	redirect := func(raw string) string {
		u, err := url.Parse(raw)
		require.NoError(t, err, "parse identity file URL %q", raw)
		u.Host = addr
		return u.String()
	}

	content.ZtAPI = redirect(content.ZtAPI)
	for i, api := range content.ZtAPIs {
		content.ZtAPIs[i] = redirect(api)
	}

	raw, err := json.Marshal(content)
	require.NoError(t, err, "marshal doctored identity file")
	require.NoError(t, os.WriteFile(path, raw, 0o600), "write doctored identity file %s", path)
}

// AssertNoIdentityFile asserts a failed enrollment left no identity file in
// zet's identity dir.
func AssertNoIdentityFile(t *testing.T, zet *ZET, name string) {
	idPath := filepath.Join(zet.RootDir, "identities", name+".json")
	require.NoFileExists(t, idPath)
}

func AssertValidJwtEnrolledIdentityFile(t *testing.T, path string) {
	content := ReadIdentityFile(t, path)
	require.NotEmpty(t, content.ZtAPI, "identity file ztAPI empty")
	require.NotEmpty(t, content.ID.Cert, "identity file id.cert empty")
	require.NotEmpty(t, content.ID.Key, "identity file id.key empty")
	require.NotEmpty(t, content.ID.CA, "identity file id.ca empty")
}

func AssertValidUrlEnrolledIdentityFile(t *testing.T, path string, mode EnrollMode) {
	content := ReadIdentityFile(t, path)
	require.NotEmpty(t, content.ZtAPI, "identity file ztAPI empty")
	require.NotEmpty(t, content.ID.CA, "identity file id.ca empty")
	switch mode {
	case EnrollModeNone, EnrollModeToken:
		require.Empty(t, content.ID.Cert, "identity file id.cert should be empty for URL enroll-to-%s", mode)
		require.Empty(t, content.ID.Key, "identity file id.key should be empty for URL enroll-to-%s", mode)
	case EnrollModeCert:
		require.NotEmpty(t, content.ID.Cert, "identity file id.cert empty")
		require.NotEmpty(t, content.ID.Key, "identity file id.key empty")
	}
}
