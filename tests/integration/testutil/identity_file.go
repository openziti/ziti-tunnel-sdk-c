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
	"os"
	"strings"
	"testing"

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
	raw, err := os.ReadFile(path)
	require.NoError(t, err, "failed to read identity file at %s", path)

	var content IdentityFileContent
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	require.NoError(t, dec.Decode(&content), "identity file at %s has unknown fields or invalid shape: %s", path, raw)
	return content
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
	case EnrollModeNone:
		require.Empty(t, content.ID.Cert, "identity file id.cert should be empty for URL enroll-to-none")
		require.Empty(t, content.ID.Key, "identity file id.key should be empty for URL enroll-to-none")
	case EnrollModeCert, EnrollModeToken:
		require.NotEmpty(t, content.ID.Cert, "identity file id.cert empty")
		require.NotEmpty(t, content.ID.Key, "identity file id.key empty")
	}
}
