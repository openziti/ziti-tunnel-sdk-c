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

//go:build linux

package testutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// CheckLsanLogs reads LSan report files under dir that were written by a ZET
// process with the given discriminator. LSan writes one file per process with
// the suffix ".<pid>", so we glob for "lsan.<pid>" files. The function fails t
// if any report contains the "detected memory leaks" marker.
func CheckLsanLogs(t *testing.T, dir, discriminator string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Logf("lsan[%s]: readdir %s: %v (no report)", discriminator, dir, err)
		return
	}
	found := false
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "lsan.") {
			continue
		}
		found = true
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			t.Logf("lsan[%s]: read %s: %v", discriminator, path, err)
			continue
		}
		if strings.Contains(string(data), "detected memory leaks") {
			t.Errorf("lsan[%s]: heap leaks detected (report: %s)\n%s", discriminator, path, data)
		} else {
			t.Logf("lsan[%s]: no leaks (%s)", discriminator, e.Name())
		}
	}
	if !found {
		t.Logf("lsan[%s]: no report files found in %s", discriminator, dir)
	}
}
