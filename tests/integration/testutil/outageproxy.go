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
	"time"
)

// OutageProxy is a TCP relay that stands in for a target address (typically
// the overlay's controller) so a test can simulate a network outage on
// demand. It is pure Go so it works the same way on every OS this suite
// targets, unlike an external chaos-proxy tool or container-network tricks.
//
// Sever black-holes traffic rather than resetting it: bytes already in
// flight on a connection open at the moment of Sever just stop moving (the
// socket is never closed), and a new inbound TCP connection is accepted -
// completing the handshake, since a pure-Go listener can't silently drop a
// SYN the way a real severed link does - but then held open and never dialed
// upstream, so it never receives a byte either. Either way, the peer gets no
// RST, no FIN, no data - it only ever finds out via its own read/write
// timeouts, same as a real partition (packets simply stop arriving). Restore
// dials upstream for every held connection and resumes relaying on both.
//
// This used to actively RST everything on Sever (SO_LINGER=0 + Close, see
// git history) for fast, deterministic reconnect attempts - but that gives a
// client immediate, clean feedback that a real outage never does, and a real
// bug (openziti/tlsuv#367) turned out to depend on that difference: it
// reproduces against a genuinely black-holed connection (confirmed against a
// podman container with its network interface disabled) but not against this
// proxy's old RST-based Sever, which apparently let clients recover too
// cleanly to hit whatever stale state the bug needs.
type OutageProxy struct {
	Addr string

	target  string
	ln      net.Listener
	severed atomic.Bool

	mu    sync.Mutex
	conns map[net.Conn]struct{}
	// held is the set of inbound connections accepted while severed - kept
	// open but never dialed upstream until Restore.
	held map[net.Conn]struct{}
}

// StartOutageProxy starts relaying listenAddr -> target and returns once
// listening. Registers cleanup with t, unless keepAlive is true - a
// debugging aid so the proxy (and so the connections routed through it)
// survives past the end of the test for live inspection; pass false for a
// real test run, so an interrupted run doesn't leak the listener.
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
func StartOutageProxy(t *testing.T, listenAddr, target string, keepAlive bool) *OutageProxy {
	t.Helper()
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		t.Fatalf("listen tcp %s for outage proxy: %v", listenAddr, err)
	}
	addr := fmt.Sprintf("localhost:%d", ln.Addr().(*net.TCPAddr).Port)

	p := &OutageProxy{Addr: addr, target: target, conns: make(map[net.Conn]struct{}), held: make(map[net.Conn]struct{}), ln: ln}
	go p.acceptLoop()
	if !keepAlive {
		t.Cleanup(func() { _ = ln.Close() })
	}
	return p
}

// Sever begins simulating an outage: nothing is closed. Bytes on connections
// already open just stop moving (see relay), and any new inbound connection
// gets accepted but held, unrelayed, until Restore - see the type doc for why
// this, not an active RST, is what's needed to reproduce openziti/tlsuv#367.
func (p *OutageProxy) Sever() {
	p.severed.Store(true)
	p.mu.Lock()
	n := len(p.conns)
	p.mu.Unlock()
	log.Printf("outageproxy: severed %s -> %s (black-holing %d already-open connection(s), holding new ones unrelayed)", p.Addr, p.target, n)
}

// Restore ends the simulated outage: relaying resumes on connections that
// were open throughout, and every held connection is dialed upstream and
// relayed for the first time.
func (p *OutageProxy) Restore() {
	p.severed.Store(false)

	p.mu.Lock()
	held := make([]net.Conn, 0, len(p.held))
	for c := range p.held {
		held = append(held, c)
	}
	p.held = make(map[net.Conn]struct{})
	p.mu.Unlock()

	for _, conn := range held {
		p.dialAndRelay(conn)
	}
	log.Printf("outageproxy: restored %s -> %s (%d held connection(s) now relaying)", p.Addr, p.target, len(held))
}

func (p *OutageProxy) acceptLoop() {
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return
		}
		if p.severed.Load() {
			// Hold silently: no dial, no data, no close - the peer only
			// learns something's wrong from its own timeouts, same as a real
			// black hole. Restore dials and relays it.
			p.mu.Lock()
			p.held[conn] = struct{}{}
			p.mu.Unlock()
			continue
		}
		p.dialAndRelay(conn)
	}
}

// dialAndRelay dials upstream for conn and starts relaying both directions.
// conn is closed (not held or tracked) if the dial itself fails - a dial
// failure means the upstream controller is unreachable, not a simulated
// outage, and every caller already only reaches this while not severed.
func (p *OutageProxy) dialAndRelay(conn net.Conn) {
	upstream, err := net.Dial("tcp", p.target)
	if err != nil {
		_ = conn.Close()
		return
	}
	p.mu.Lock()
	p.conns[conn] = struct{}{}
	p.conns[upstream] = struct{}{}
	p.mu.Unlock()
	go p.relay(conn, upstream)
	go p.relay(upstream, conn)
}

// relay copies src -> dst until either side closes or errors, then closes
// and untracks both. Polls p.severed between reads so a Sever call pauses
// forwarding mid-flight without touching either socket - data already read
// but not yet forwarded when Sever lands may still cross (a real partition
// has no such edge case), but nothing at all moves while severed.
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
		for p.severed.Load() {
			time.Sleep(50 * time.Millisecond)
		}
		_ = src.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
	}
}
