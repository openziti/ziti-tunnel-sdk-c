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
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"testing"
)

// OutageProxy is a TCP relay that stands in for a target address (typically
// the overlay's controller) so a test can simulate a network outage on
// demand. It is pure Go so it works the same way on every OS this suite
// targets, unlike an external chaos-proxy tool or container-network tricks.
//
// Sever immediately drops every connection currently relayed and refuses
// every new one for as long as it's severed - a client that reuses a
// persistent connection and just queues requests on it while the network is
// down would never actually notice the outage or attempt to reconnect, and
// the whole point is to force real reconnect attempts (repeatedly, against
// an unreachable endpoint) the way a real outage does. Restore resumes
// accepting and relaying normally.
type OutageProxy struct {
	Addr string

	target  string
	ln      net.Listener
	severed atomic.Bool

	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

// StartOutageProxy starts relaying listenAddr -> target and returns once
// listening. Registers cleanup with t.
//
// listenAddr is a "host:port" or "host:0" (OS-assigned port) to bind - pass
// a fixed port when something else (e.g. Overlay.CtrlPort, matched with
// Overlay.BindCtrlPort routing the real controller elsewhere) needs to know
// the proxy's address in advance, before it's actually started.
//
// Addr is reported as "localhost:<port>", not the raw listenAddr host if
// that was an IP: a controller whose edge.api.address is set to this Addr
// (see Overlay.SetEdgeApiAddress) validates incoming requests' Host header
// against it, and "127.0.0.1" and "localhost" are different strings for
// that exact-match purpose even though they resolve to the same loopback
// address - discovered the hard way as a broken admin login.
func StartOutageProxy(t *testing.T, listenAddr, target string) *OutageProxy {
	t.Helper()
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		t.Fatalf("listen tcp %s for outage proxy: %v", listenAddr, err)
	}
	addr := fmt.Sprintf("localhost:%d", ln.Addr().(*net.TCPAddr).Port)

	p := &OutageProxy{Addr: addr, target: target, ln: ln, conns: make(map[net.Conn]struct{})}
	go p.acceptLoop()
	t.Cleanup(func() { _ = ln.Close() })
	return p
}

// Sever begins simulating an outage: every connection currently relayed is
// closed (RST, not a graceful FIN - see resetClose) and every new inbound
// connection is refused the same way until Restore.
func (p *OutageProxy) Sever() {
	p.severed.Store(true)

	p.mu.Lock()
	conns := make([]net.Conn, 0, len(p.conns))
	for c := range p.conns {
		conns = append(conns, c)
	}
	p.mu.Unlock()
	for _, c := range conns {
		resetClose(c)
	}
	log.Printf("outageproxy: severed %s -> %s (dropped %d connection(s))", p.Addr, p.target, len(conns))
}

// Restore ends the simulated outage: new connections are accepted and
// relayed again.
func (p *OutageProxy) Restore() {
	p.severed.Store(false)
	log.Printf("outageproxy: restored %s -> %s", p.Addr, p.target)
}

func (p *OutageProxy) acceptLoop() {
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return
		}
		if p.severed.Load() {
			// a real outage also means fresh connection attempts don't land.
			resetClose(conn)
			continue
		}
		upstream, err := net.Dial("tcp", p.target)
		if err != nil {
			resetClose(conn)
			continue
		}
		p.mu.Lock()
		p.conns[conn] = struct{}{}
		p.conns[upstream] = struct{}{}
		p.mu.Unlock()
		go p.relay(conn, upstream)
		go p.relay(upstream, conn)
	}
}

// relay copies src -> dst until either side closes or errors, then closes
// and untracks both.
func (p *OutageProxy) relay(dst, src net.Conn) {
	defer func() {
		_ = dst.Close()
		_ = src.Close()
		p.mu.Lock()
		delete(p.conns, dst)
		delete(p.conns, src)
		p.mu.Unlock()
	}()
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// resetClose closes conn with SO_LINGER=0, forcing an RST instead of a
// graceful FIN so the peer's TLS handshake or read fails immediately
// (ECONNRESET) rather than sitting on a timeout waiting for a peer that
// closed cleanly. Mirrors DeadController's technique.
func resetClose(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	_ = conn.Close()
}
