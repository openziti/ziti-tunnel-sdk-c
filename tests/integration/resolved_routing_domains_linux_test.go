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

package integration_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/openziti/ziti-tunnel-sdk-c/tests/integration/testutil"
	"github.com/stretchr/testify/require"
)

// TestResolvedRoutingDomains checks that, with systemd-resolved and no --dns-upstream, an intercepted
// hostname becomes a routing domain of the TUN link, so resolved asks only ziti for it, and that the
// names below it which ziti does not intercept are forwarded to the system's DNS servers.
// See https://github.com/openziti/ziti-tunnel-sdk-c/issues/798
//
// Requires root/CAP_NET_ADMIN and systemd-resolved.
func TestResolvedRoutingDomains(t *testing.T) {
	requireMultiTunnel(t)
	requireResolvedServers(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	interceptZET, hostZET := state.zetClient, state.zetHost
	hostname := strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-")) + ".resolved.ziti"
	setupT2TService(t, ctx, interceptZET, hostZET, t2tNames(t), "tcp", "127.0.0.1", 21003, hostname, 21003)

	tun, err := tunInterface(interceptZET)
	require.NoError(t, err, "find TUN of the intercepting ZET")

	// the routing domain follows the service, applied once the ZET has it
	var domains string
	for !strings.Contains(domains, "~"+hostname) {
		domains = resolvectl(t, "domain", tun)
		select {
		case <-ctx.Done():
			t.Fatalf("%s never became a routing domain of %s: %q\n%s", hostname, tun, domains, interceptZET.LogFile())
		case <-time.After(500 * time.Millisecond):
		}
	}

	// with only the system's servers to forward to, the link carries just the intercepted names.
	// "Protocols: -DefaultRoute" (systemd 251+) or "Default Route: no" / "DefaultRoute setting: no";
	// before 240 there is no such setting, and a link with routing-only domains gets no other names
	status := resolvectl(t, "status", tun)
	if regexp.MustCompile(`(?i)default ?route`).MatchString(status) {
		require.Regexp(t, regexp.MustCompile(`(?i)-DefaultRoute\b|default ?route[^:\n]*:\s*no`), status,
			"%s should not be a default route without --dns-upstream\n%s", tun, interceptZET.LogFile())
	}

	dnsServer, err := interceptZET.DNSServer()
	require.NoError(t, err, "get intercept ZET DNS server")
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, net.JoinHostPort(dnsServer, "53"))
		},
	}

	// a name below the intercepted one reaches only ziti, which must forward it rather than refuse it.
	// ".ziti" is not delegated, so the system's servers answer NXDOMAIN
	_, err = resolver.LookupIP(ctx, "ip4", "below."+hostname)
	var dnsErr *net.DNSError
	require.True(t, errors.As(err, &dnsErr) && dnsErr.IsNotFound,
		"below.%s should be forwarded and not found, got: %v\n%s", hostname, err, interceptZET.LogFile())

	// and the intercepted name itself resolves to the ZET through systemd-resolved
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", hostname)
	require.NoError(t, err, "resolve %s through systemd-resolved\n%s", hostname, interceptZET.LogFile())
	prefix := netip.MustParsePrefix(interceptZET.DNSRange)
	addr, _ := netip.AddrFromSlice(ips[0].To4())
	require.True(t, prefix.Masked().Contains(addr), "%s resolved to %s, outside %s", hostname, addr, prefix)
}

// requireResolvedServers skips unless systemd-resolved runs and has servers of its own to forward to.
func requireResolvedServers(t *testing.T) {
	if _, err := exec.LookPath("resolvectl"); err != nil {
		t.Skip("resolvectl not found")
	}
	if err := exec.Command("resolvectl", "status").Run(); err != nil {
		t.Skipf("systemd-resolved is not running: %v", err)
	}
	f, err := os.Open("/run/systemd/resolve/resolv.conf")
	if err != nil {
		t.Skipf("no systemd-resolved upstream list: %v", err)
	}
	defer f.Close()
	zetServers := map[string]bool{}
	for _, z := range []*testutil.ZET{state.zetClient, state.zetHost} {
		if s, err := z.DNSServer(); err == nil {
			zetServers[s] = true
		}
	}
	for s := bufio.NewScanner(f); s.Scan(); {
		fields := strings.Fields(s.Text())
		if len(fields) == 2 && fields[0] == "nameserver" && !zetServers[fields[1]] {
			return
		}
	}
	t.Skip("systemd-resolved has no DNS servers besides the ZETs")
}

// tunInterface returns the name of the link that holds the first address of the ZET's range.
func tunInterface(z *testutil.ZET) (string, error) {
	tunIP := netip.MustParsePrefix(z.DNSRange).Addr()
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr() == tunIP {
				return iface.Name, nil
			}
		}
	}
	return "", fmt.Errorf("no link has %s", tunIP)
}

func resolvectl(t *testing.T, args ...string) string {
	out, err := exec.Command("resolvectl", args...).CombinedOutput()
	require.NoError(t, err, "resolvectl %s: %s", strings.Join(args, " "), out)
	return string(out)
}
