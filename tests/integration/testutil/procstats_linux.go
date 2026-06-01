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
	"fmt"
	"os"
)

// ProcStats holds per-process resource counts sampled at a point in time.
type ProcStats struct {
	FDCount int // number of open file descriptors
}

// SampleProcStats reads the open FD count for pid from /proc.
func SampleProcStats(pid int) (ProcStats, error) {
	var s ProcStats
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return s, fmt.Errorf("readdir %s: %w", fdDir, err)
	}
	s.FDCount = len(entries)
	return s, nil
}
