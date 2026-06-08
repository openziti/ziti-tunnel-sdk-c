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
	"testing"
	"time"
)

const TestTimeout = 5 * time.Second

func RunWithTimeout(t *testing.T, f func(t *testing.T)) {
	t.Helper()
	RunWithTimeoutOf(t, TestTimeout, f)
}

func RunWithTimeoutOf(t *testing.T, timeout time.Duration, f func(t *testing.T)) {
	t.Helper()
	done := make(chan any, 1)

	go func() {
		defer func() { done <- recover() }()
		f(t)
	}()

	select {
	case p := <-done:
		if p != nil {
			panic(p)
		}
	case <-time.After(timeout):
		t.Fatalf("test %s timed out after %s", t.Name(), timeout)
	}
}
