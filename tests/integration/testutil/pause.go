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
	"bufio"
	"fmt"
	"os"
)

// Pause blocks until ENTER is pressed at the console. `go test` redirects the
// test binary's stdin to nul, so this opens CONIN$ directly (Windows-only).
func Pause(msg string) {
	tty, err := os.OpenFile("CONIN$", os.O_RDONLY, 0)
	if err != nil {
		fmt.Printf("Pause: open CONIN$: %v\n", err)
		return
	}
	defer tty.Close()
	fmt.Print(msg)
	_, _ = bufio.NewReader(tty).ReadString('\n')
}
