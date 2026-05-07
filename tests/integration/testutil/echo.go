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
	"io"
	"net"
	"testing"
)

// Echo is a local echo server for test use.
type Echo struct {
	// Addr is the host:port the server is listening on.
	Addr string
}

// StartTCPEcho starts a TCP echo server on 127.0.0.1:0 and registers cleanup with t.
// Each connection is echoed in its own goroutine.
func StartTCPEcho(t *testing.T) *Echo {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp for echo: %v", err)
	}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	t.Cleanup(func() { _ = l.Close() })
	return &Echo{Addr: l.Addr().String()}
}

// StartUDPEcho starts a UDP echo server on 127.0.0.1:0 and registers cleanup with t.
// Each received datagram is echoed back to the sender.
func StartUDPEcho(t *testing.T) *Echo {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp for echo: %v", err)
	}
	go func() {
		buf := make([]byte, 65536)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteTo(buf[:n], addr)
		}
	}()
	t.Cleanup(func() { _ = conn.Close() })
	return &Echo{Addr: conn.LocalAddr().String()}
}
