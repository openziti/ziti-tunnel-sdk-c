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
	"regexp"
	"strconv"
	"strings"
)

// ZitiConnSummary holds the leak-relevant subset of one identity's ziti dump.
type ZitiConnSummary struct {
	Identifier   string
	ActiveConns  int // root-level conn[] entries in the Connections section
	TotalRecvBuf int // sum of recv_buff[N] across all connections
}

var (
	// Matches root-level conn lines (not indented) in the Connections section.
	// Both transport ("conn[id/marker]: state[...]") and server ("conn[id]: server ...") forms.
	rootConnRe = regexp.MustCompile(`^conn\[`)
	recvBufRe  = regexp.MustCompile(`recv_buff\[(\d+)\]`)
)

// ParseZitiDump extracts ZitiConnSummary from the per-identity map returned by
// ZitiDump (DumpPath=""). The per-identity values are free-form text from
// ziti_dump() in ziti-sdk-c; parsing is tolerant — format changes degrade to
// zero counts rather than errors.
func ParseZitiDump(data map[string]string) []ZitiConnSummary {
	result := make([]ZitiConnSummary, 0, len(data))
	for id, text := range data {
		result = append(result, parseOneIdentityDump(id, text))
	}
	return result
}

func parseOneIdentityDump(identifier, text string) ZitiConnSummary {
	s := ZitiConnSummary{Identifier: identifier}
	inConns := false
	for _, line := range strings.Split(text, "\n") {
		// Detect entry into the Connections section.
		if strings.TrimSpace(line) == "Connections:" {
			inConns = true
			continue
		}
		// A "=================" rule ends the current section.
		if inConns && strings.HasPrefix(strings.TrimSpace(line), "=") {
			break
		}
		if !inConns {
			continue
		}
		if rootConnRe.MatchString(line) {
			s.ActiveConns++
		}
		if m := recvBufRe.FindStringSubmatch(line); m != nil {
			if n, err := strconv.Atoi(m[1]); err == nil {
				s.TotalRecvBuf += n
			}
		}
	}
	return s
}
