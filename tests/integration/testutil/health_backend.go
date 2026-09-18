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
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
)

// ControllableBackend is a TCP (echo) or HTTP server that a health-check test can take
// down and bring back up on the same address, to exercise host.v1 portChecks/httpChecks
// failing and recovering against a stable target. Unlike Echo (which only ever starts),
// this is what lets a test simulate a backend outage without the hosted service's
// config (and therefore its portCheck/httpCheck address/url) having to change.
type ControllableBackend struct {
	t      *testing.T
	addr   string // host:port, fixed for the backend's lifetime
	isHTTP bool

	mu       sync.Mutex
	listener net.Listener // nil when stopped
	httpSrv  *http.Server // nil when stopped or not HTTP

	status atomic.Int64
	body   atomic.Value // string
}

// StartTCPBackend starts a TCP accept-and-echo server on an ephemeral port. Stop/Start
// take it down and bring it back up on that same address.
func StartTCPBackend(t *testing.T) *ControllableBackend {
	return newControllableBackend(t, false)
}

// StartHTTPBackend starts an HTTP server on an ephemeral port, initially responding
// 200 "ok" to every request; see SetResponse to change that. Controllable the same way
// as StartTCPBackend.
func StartHTTPBackend(t *testing.T) *ControllableBackend {
	return newControllableBackend(t, true)
}

func newControllableBackend(t *testing.T, isHTTP bool) *ControllableBackend {
	b := &ControllableBackend{t: t, isHTTP: isHTTP}
	b.status.Store(200)
	b.body.Store("ok")

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for controllable backend: %v", err)
	}
	b.addr = l.Addr().String()
	b.attach(l)
	t.Cleanup(b.Stop)
	return b
}

// Addr returns the fixed host:port this backend listens on while running.
func (b *ControllableBackend) Addr() string {
	return b.addr
}

// Stop closes the listener (and, for HTTP, aborts any active connections), simulating
// the backend going down. Connection attempts to Addr() fail until Start is called
// again. Safe to call when already stopped.
func (b *ControllableBackend) Stop() {
	b.mu.Lock()
	l, srv := b.listener, b.httpSrv
	b.listener, b.httpSrv = nil, nil
	b.mu.Unlock()

	if srv != nil {
		_ = srv.Close()
	} else if l != nil {
		_ = l.Close()
	}
}

// Start re-listens on Addr(), simulating the backend recovering. No-op if already
// running.
func (b *ControllableBackend) Start() {
	b.mu.Lock()
	running := b.listener != nil
	b.mu.Unlock()
	if running {
		return
	}

	l, err := net.Listen("tcp", b.addr)
	if err != nil {
		b.t.Fatalf("relisten controllable backend on %s: %v", b.addr, err)
	}
	b.attach(l)
}

// SetResponse changes the status code and body an HTTP backend returns to every
// subsequent request. No-op on a TCP (echo) backend.
func (b *ControllableBackend) SetResponse(status int, body string) {
	b.status.Store(int64(status))
	b.body.Store(body)
}

func (b *ControllableBackend) attach(l net.Listener) {
	b.mu.Lock()
	b.listener = l
	var srv *http.Server
	if b.isHTTP {
		srv = &http.Server{Handler: http.HandlerFunc(b.serveHTTP)}
		b.httpSrv = srv
	}
	b.mu.Unlock()

	if srv != nil {
		go func() { _ = srv.Serve(l) }()
		return
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
}

func (b *ControllableBackend) serveHTTP(w http.ResponseWriter, _ *http.Request) {
	status := int(b.status.Load())
	body, _ := b.body.Load().(string)
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}
