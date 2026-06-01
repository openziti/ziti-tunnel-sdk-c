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

//go:build darwin

package testutil

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// ProcStats holds per-process resource counts sampled at a point in time.
type ProcStats struct {
	FDCount int // number of open file descriptors
}

// SampleProcStats reads the open FD count for pid via lsof.
func SampleProcStats(pid int) (ProcStats, error) {
	var s ProcStats
	out, err := exec.Command("lsof", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return s, fmt.Errorf("lsof -p %d: %w", pid, err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) > 1 {
		s.FDCount = len(lines) - 1 // subtract header line
	}
	return s, nil
}
