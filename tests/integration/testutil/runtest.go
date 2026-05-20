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
	"testing"
	"time"
)

const TestTimeout = 5 * time.Second

func RunTestWithTimeout(t *testing.T, name string, f func(t *testing.T)) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	t.Run(name, f)
	t.Cleanup(cancel)
	return ctx
}
