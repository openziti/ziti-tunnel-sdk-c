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
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// HACluster is a hand-built multi-node HA controller cluster: each node's
// advertised addresses (both the raft/ctrl-channel one and the edge-API one)
// are routed through that node's own dedicated OutageProxy, so SeverAll/
// RestoreAll can black-hole the whole cluster at once - the same address/
// proxy trick Overlay.BindCtrlPort uses for a single node, generalized to N
// nodes.
//
// Deliberately does NOT use `ziti edge quickstart cluster`. Raft persists a
// member's advertised address the moment it first joins (via
// `ziti agent cluster init`/`add`), and there is no supported way to change
// it afterward - confirmed live: redirecting an already-joined member's
// address (config edit + restart) produces a permanent duplicate raft entry,
// the old address staying on as a voter while the new one joins separately
// as a non-voting entry. `quickstart`'s own `--configure-and-exit` doesn't
// give a way around this either: for a join node it performs a real
// `agent cluster add` against whatever address is live at that moment, not a
// dry run - so a node's config must already carry its final, proxied address
// before that one-shot join/init ever happens, for every node including the
// first.
//
// Built instead from the same primitives `ziti run quickstart`/`join` use
// internally under the hood, each a stable, public CLI command:
//   - `ziti pki create ca/intermediate/server/client` for PKI - a join node's
//     PKI generation is purely local (reuses the existing root CA already on
//     disk, no network contact), confirmed by reading quickstart's own
//     CreateMinimalPki.
//   - `ziti controller run <config>` to start a bare controller from an
//     already-correct config (no cluster init/join of its own).
//   - `ziti agent cluster init` (node 0) or `ziti agent cluster add` (nodes
//     1..N-1), issued over that node's own local agent socket, to perform
//     the one-shot join with the address already right.
//   - `ziti edge create edge-router` / `ziti create config router edge` /
//     `ziti router enroll` / `ziti router run` for the one shared edge
//     router - unlike the controller nodes, the router isn't a raft member
//     and its own address is never proxied (this cluster's outage
//     simulation only targets controller reachability, matching the
//     single-node outage test's scope).
type HACluster struct {
	ZitiBin     string
	Username    string
	Password    string
	TrustDomain string
	// Home is this cluster's own directory - PKI, per-node config/logs, the
	// router's config/log, and this cluster's own ziti CLI session all live
	// under it.
	Home string
	// Size is the number of controller nodes (3-9, matching quickstart
	// cluster's own limits).
	Size int
	// BindPortBase/ProxyPortBase: node i binds on BindPortBase+i (real,
	// reachable only through its own proxy) and advertises through a proxy
	// listening on ProxyPortBase+i. RouterPort is the one shared router's
	// edge listener port (not proxied - see the type doc).
	BindPortBase  int
	ProxyPortBase int
	RouterPort    int
	// OidcAccessTokenDuration/OidcRefreshTokenDuration, if the access
	// duration is nonzero, shorten every node's edge.oidc token lifetimes
	// before that node ever starts (see setOidcTokenDurationsInConfig) -
	// same "configure once, at birth" approach as the proxied address, so a
	// caller doesn't need a separate restart cycle to apply it. Zero means
	// leave the controller's own defaults.
	OidcAccessTokenDuration  time.Duration
	OidcRefreshTokenDuration time.Duration
	// DetachSession, if true, starts every node/router process in its own
	// session/process group (see detachSession) so it survives a signal
	// sent to this test process's group - a debugging aid, matching
	// Overlay.DetachSession. Leave false for a real test run.
	DetachSession bool

	nodes      []*haNode
	routerName string
	routerCmd  *exec.Cmd
	routerLog  *os.File
	routerDone chan error
}

type haNode struct {
	instanceID string
	configPath string
	agentSock  string
	bindPort   int
	proxyPort  int
	proxy      *OutageProxy
	cmd        *exec.Cmd
	logFile    *os.File
	done       chan error
}

// ControllerHostPort is node 0's proxy address - what admin CLI calls and
// enrollment JWTs should be reached through.
func (c *HACluster) ControllerHostPort() string {
	return fmt.Sprintf("https://localhost:%d", c.nodes[0].proxyPort)
}

func (c *HACluster) cliConfigDir() string { return filepath.Join(c.Home, "cli-config") }

// execZiti mirrors Overlay.execZiti, scoped to this cluster's own CLI
// session directory.
func (c *HACluster) execZiti(cmd string, args ...string) ([]byte, error) {
	tokens := strings.Fields(cmd)
	argv := make([]string, 0, len(tokens))
	i := 0
	for _, tok := range tokens {
		if tok != "%s" {
			argv = append(argv, tok)
			continue
		}
		if i >= len(args) {
			return nil, fmt.Errorf("execZiti: %d args for more placeholders in %q", len(args), cmd)
		}
		argv = append(argv, args[i])
		i++
	}
	if i != len(args) {
		return nil, fmt.Errorf("execZiti: %d args for %d placeholders in %q", len(args), i, cmd)
	}

	ziti := exec.Command(c.ZitiBin, argv...)
	ziti.Env = append(os.Environ(), "ZITI_CONFIG_DIR="+c.cliConfigDir())
	out, err := ziti.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s %v: %w\n%s", c.ZitiBin, argv, err, out)
	}
	return out, nil
}

// Start brings up all Size controller nodes (each already advertising
// through its own proxy from the moment it joins), one shared edge router,
// and logs in as admin through node 0's proxy for subsequent execZiti calls.
func (c *HACluster) Start(t *testing.T) error {
	t.Helper()
	if c.Size < 3 || c.Size > 9 {
		return fmt.Errorf("HACluster.Size must be 3-9, got %d", c.Size)
	}
	if c.TrustDomain == "" {
		c.TrustDomain = "quickstart"
	}
	if c.Username == "" {
		c.Username = "admin"
	}
	if c.Password == "" {
		c.Password = "admin"
	}
	if err := os.MkdirAll(c.Home, 0o755); err != nil {
		return fmt.Errorf("mkdir home: %w", err)
	}

	log.Printf("hacluster: capturing a config template")
	template, err := c.captureConfigTemplate()
	if err != nil {
		return fmt.Errorf("capture config template: %w", err)
	}

	pkiDir := filepath.Join(c.Home, "pki")
	if err := c.createRootCA(pkiDir); err != nil {
		return fmt.Errorf("create root CA: %w", err)
	}

	c.nodes = make([]*haNode, c.Size)

	log.Printf("hacluster: starting node 1 of %d (bootstrap)", c.Size)
	node0, err := c.startNode(t, 0, template, pkiDir)
	if err != nil {
		return fmt.Errorf("start node 0: %w", err)
	}
	c.nodes[0] = node0
	if err := c.execAgentInit(node0); err != nil {
		return fmt.Errorf("cluster init on node 0: %w", err)
	}

	if _, err := c.execZiti("edge login %s -u %s -p %s --yes",
		c.ControllerHostPort(), c.Username, c.Password); err != nil {
		return fmt.Errorf("admin login: %w", err)
	}

	for i := 1; i < c.Size; i++ {
		log.Printf("hacluster: starting node %d of %d", i+1, c.Size)
		node, err := c.startNode(t, i, template, pkiDir)
		if err != nil {
			return fmt.Errorf("start node %d: %w", i, err)
		}
		c.nodes[i] = node
		if err := c.execAgentJoin(node); err != nil {
			return fmt.Errorf("cluster join for node %d: %w", i, err)
		}
	}

	if err := c.WaitForClusterLeader(); err != nil {
		return fmt.Errorf("wait for cluster leader: %w", err)
	}

	if err := c.configureOverlay(); err != nil {
		return fmt.Errorf("configure overlay: %w", err)
	}

	log.Printf("hacluster: starting shared edge router")
	if err := c.startRouter(t); err != nil {
		return fmt.Errorf("start router: %w", err)
	}

	log.Printf("hacluster: ready (%d nodes, controller reachable at %s)", c.Size, c.ControllerHostPort())
	return nil
}

// configureOverlay creates the two default policies `ziti edge quickstart`
// normally creates as part of its own bootstrap (configureOverlay in
// quickstart.go) - since HACluster never runs quickstart at all (see the
// type doc), nothing else creates them. Without these, no identity is
// authorized to reach any edge router at all: `/current-identity/edge-routers`
// returns an empty list forever, `edge_routers_cb`'s success path (the only
// thing that calls ziti_channel_connect for identity-level discovery) never
// has anything to iterate over, and the router channel never connects -
// confirmed live: it doesn't just fail to *reconnect* after an outage, it
// never connects even once, from the very first enrollment, only masked
// because the pre-outage checks in network_outage_test.go use the weaker
// controller-level "connected" signal (any single controller HTTP call
// succeeding), not the router-level one.
func (c *HACluster) configureOverlay() error {
	if _, err := c.execZiti("edge create edge-router-policy all-endpoints-public-routers %s %s",
		"--edge-router-roles=#public", "--identity-roles=#all"); err != nil {
		return fmt.Errorf("create edge-router-policy: %w", err)
	}
	if _, err := c.execZiti("edge create service-edge-router-policy all-routers-all-services %s %s",
		"--edge-router-roles=#all", "--service-roles=#all"); err != nil {
		return fmt.Errorf("create service-edge-router-policy: %w", err)
	}
	return nil
}

// haClusterTemplateDir/haClusterTemplateInstanceID name the disposable
// throwaway run captureConfigTemplate uses, kept deliberately distinct from
// each other (not both "template", as an earlier version of this file had
// it) so renderNodeConfig can tell apart the two different path shapes that
// throwaway run produces - see renderNodeConfig's own doc comment for why
// that distinction matters.
const (
	haClusterTemplateDir        = "template-capture"
	haClusterTemplateInstanceID = "node"
)

// captureConfigTemplate runs a disposable single-node `ziti run quickstart
// --configure-and-exit` (never real-joined to anything, its whole home
// directory removed immediately after) purely to get a real ctrl.yaml's
// structure to template every real node's config from - this avoids hand-
// authoring the YAML shape from scratch, which would tie this harness to
// ziti's internal config format even more tightly than it already is.
func (c *HACluster) captureConfigTemplate() (string, error) {
	templateHome := c.templateHomePath()
	defer func() { _ = os.RemoveAll(templateHome) }()

	// Comfortably above any real node's bind port range so this disposable
	// run can never collide with one of them.
	ctrlPort := c.BindPortBase + 1000
	routerPort := c.BindPortBase + 1001

	cmd := exec.Command(c.ZitiBin, "run", "quickstart",
		"--home", templateHome,
		"--instance-id", haClusterTemplateInstanceID,
		"--ctrl-address", "localhost",
		"--ctrl-port", strconv.Itoa(ctrlPort),
		"--router-address", "localhost",
		"--router-port", strconv.Itoa(routerPort),
		"--trust-domain", c.TrustDomain,
		"--username", c.Username,
		"--password", c.Password,
		"--configure-and-exit",
	)
	cmd.Env = append(os.Environ(), "ZITI_CONFIG_DIR="+filepath.Join(templateHome, "cli-config"))
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("template quickstart run: %w\n%s", err, out)
	}

	raw, err := os.ReadFile(filepath.Join(templateHome, haClusterTemplateInstanceID, "ctrl.yaml"))
	if err != nil {
		return "", fmt.Errorf("read template config: %w", err)
	}
	return string(raw), nil
}

func (c *HACluster) createRootCA(pkiDir string) error {
	rootCert := filepath.Join(pkiDir, "root-ca", "certs", "root-ca.cert")
	if _, err := os.Stat(rootCert); err == nil {
		return nil
	}
	cmd := exec.Command(c.ZitiBin, "pki", "create", "ca",
		"--pki-root", pkiDir,
		"--ca-file", "root-ca",
		"--ca-name", "root-ca",
		"--trust-domain", c.TrustDomain,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w\n%s", err, out)
	}
	return nil
}

// createNodePki generates instanceID's own intermediate CA plus server/client
// certs, signed by the cluster's shared root CA - purely local, no network
// contact, mirroring quickstart's own CreateMinimalPki for a join node.
func (c *HACluster) createNodePki(pkiDir, intermediateName, instanceID string) error {
	sid := fmt.Sprintf("spiffe://%s/controller/%s", c.TrustDomain, instanceID)
	steps := [][]string{
		{"pki", "create", "intermediate",
			"--pki-root", pkiDir, "--ca-name", "root-ca",
			"--intermediate-name", intermediateName, "--intermediate-file", intermediateName,
			"--max-path-len", "1"},
		{"pki", "create", "server",
			"--pki-root", pkiDir, "--ca-name", intermediateName,
			"--server-name", instanceID, "--server-file", "server",
			"--dns", "localhost", "--ip", "127.0.0.1,::1", "--spiffe-id", sid},
		{"pki", "create", "client",
			"--pki-root", pkiDir, "--ca-name", intermediateName,
			"--client-name", instanceID, "--client-file", "client",
			"--key-file", "server", "--spiffe-id", sid},
	}
	for _, args := range steps {
		cmd := exec.Command(c.ZitiBin, args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %w\n%s", strings.Join(args, " "), err, out)
		}
	}
	return nil
}

var (
	haClusterBindAddrRE      = regexp.MustCompile(`(listener: *tls:0\.0\.0\.0:|interface: 0\.0\.0\.0:)\d+`)
	haClusterAdvertiseAddrRE = regexp.MustCompile(`(address: |advertiseAddress: tls:)localhost:\d+`)
)

// renderNodeConfig substitutes the captured template with this node's own
// instance-id, ports, data dir, and PKI paths. The advertised address (both
// ctrl.options.advertiseAddress and edge.api.address/its bindPoint) is set
// to this node's own proxy port in this one pass, before the config is ever
// written to disk - never edited in place afterward, since that's exactly
// what corrupts raft's persisted membership (see the type doc).
//
// Two distinct path prefixes need fixing up, not one blanket replace:
// quickstart builds every path under --home via path.Join (always "/"
// between components, regardless of what separator convention --home's own
// value happens to use), giving the throwaway capture run's dataDir a
// deeper prefix (<capture-home>/node/raft) than its shared pki dir
// (<capture-home>/pki/...) - a single "replace the shared substring" pass
// can't turn both into this node's own equivalents at once without also
// wrongly inserting an instance segment into the pki paths (confirmed live:
// an earlier version of this file used "template" for both the capture
// run's directory name and its instance-id, so a single blanket replace of
// "/template/" corrupted the pki paths too).
//
// The two prefixes also don't share a separator convention on Windows:
// dataDir's value comes from --home verbatim (create_config.go's
// data.ZitiHome), so templateInstHome - built the same way here via
// filepath.Join - matches it natively (backslash-joined). The PKI cert/key
// fields, though, are run through ziti's helpers.NormalizePath first
// (create_config_controller.go), which unconditionally replaces "\" with
// "/" specifically because these values sit inside double-quoted YAML
// scalars, where a raw backslash starts an escape sequence - so the
// template's actual PKI path text is forward-slash-only even on Windows,
// never matching a filepath.Join-built search string there. Confirmed live:
// this is exactly what left a real node's config still pointing at the
// already-deleted template-capture PKI dir on Windows CI, since only the
// backslash-native replace was attempted. Matching (and replacing with) the
// slash-normalized form too fixes this without touching non-Windows
// behavior, where ToSlash is a no-op.
// Both prefix substitutions below are verified, not blind: a silent no-op
// match failure is exactly how the PKI-path bug got past review the first
// time (see the fix above), and it's cheap to confirm the prefix is actually
// there before betting the rest of the config on it. On a miss, this dumps
// the whole captured template so the actual (as opposed to assumed)
// separator/normalization convention is visible directly in the failure,
// rather than surfacing 30+ seconds later as an unrelated agent-socket
// timeout with no clue why the node's on-disk paths are wrong.
func (c *HACluster) renderNodeConfig(template, instanceID string, bindPort, proxyPort int, intermediateName string) (string, error) {
	templateHome := c.templateHomePath()
	templateInstHome := templateHome + "/" + haClusterTemplateInstanceID
	templatePkiDir := templateHome + "/pki"

	cfg := template
	if !strings.Contains(cfg, templateInstHome) {
		return "", fmt.Errorf("renderNodeConfig: dataDir prefix %q not found in captured template (%d bytes):\n%s",
			templateInstHome, len(cfg), cfg)
	}
	cfg = strings.ReplaceAll(cfg, templateInstHome, c.Home+"/"+instanceID)

	pkiFromSlash := filepath.ToSlash(templatePkiDir)
	switch {
	case strings.Contains(cfg, pkiFromSlash):
		cfg = strings.ReplaceAll(cfg, pkiFromSlash, filepath.ToSlash(c.Home)+"/pki")
	case strings.Contains(cfg, templatePkiDir):
		cfg = strings.ReplaceAll(cfg, templatePkiDir, c.Home+"/pki")
	default:
		return "", fmt.Errorf("renderNodeConfig: pki dir prefix %q (native) / %q (slash-normalized) not found in captured template (%d bytes):\n%s",
			templatePkiDir, pkiFromSlash, len(cfg), cfg)
	}

	cfg = strings.ReplaceAll(cfg, "intermediate-ca-"+haClusterTemplateInstanceID, intermediateName)
	cfg = haClusterBindAddrRE.ReplaceAllString(cfg, fmt.Sprintf("${1}%d", bindPort))
	cfg = haClusterAdvertiseAddrRE.ReplaceAllString(cfg, fmt.Sprintf("${1}localhost:%d", proxyPort))
	return cfg, nil
}

// templateHomePath is the --home directory captureConfigTemplate's
// throwaway run used - shared with renderNodeConfig so both agree on the
// exact prefix to search for.
func (c *HACluster) templateHomePath() string {
	return filepath.Join(c.Home, haClusterTemplateDir)
}

// startNode generates node idx's own PKI, writes its config from the
// template with its own instance-id/ports/paths substituted, starts its
// OutageProxy, and starts its bare controller process - but does not join it
// to the cluster; see execAgentInit/execAgentJoin.
func (c *HACluster) startNode(t *testing.T, idx int, template, pkiDir string) (*haNode, error) {
	t.Helper()
	instanceID := fmt.Sprintf("instance-%d", idx+1)
	bindPort := c.BindPortBase + idx
	proxyPort := c.ProxyPortBase + idx
	intermediateName := "intermediate-ca-" + instanceID

	if err := c.createNodePki(pkiDir, intermediateName, instanceID); err != nil {
		return nil, fmt.Errorf("create PKI: %w", err)
	}

	instHome := filepath.Join(c.Home, instanceID)
	if err := os.MkdirAll(instHome, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir instance home: %w", err)
	}
	configPath := filepath.Join(instHome, "ctrl.yaml")
	cfg, err := c.renderNodeConfig(template, instanceID, bindPort, proxyPort, intermediateName)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(configPath, []byte(cfg), 0o600); err != nil {
		return nil, fmt.Errorf("write config: %w", err)
	}
	if c.OidcAccessTokenDuration != 0 {
		if err := setOidcTokenDurationsInConfig(configPath, c.OidcAccessTokenDuration, c.OidcRefreshTokenDuration); err != nil {
			return nil, fmt.Errorf("set oidc token durations: %w", err)
		}
	}

	proxy := StartOutageProxy(t,
		fmt.Sprintf("localhost:%d", proxyPort),
		fmt.Sprintf("localhost:%d", bindPort),
		c.DetachSession)

	agentSock := filepath.Join(os.TempDir(), fmt.Sprintf("ziti-hacluster-%s-%d.sock", instanceID, os.Getpid()))
	_ = os.Remove(agentSock)

	logFile, err := os.OpenFile(filepath.Join(instHome, "controller.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}

	cmd := exec.Command(c.ZitiBin, "controller", "run", configPath, "--cli-agent-addr", "unix:"+agentSock)
	if c.DetachSession {
		detachSession(cmd)
	}
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return nil, fmt.Errorf("start controller: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	node := &haNode{
		instanceID: instanceID,
		configPath: configPath,
		agentSock:  agentSock,
		bindPort:   bindPort,
		proxyPort:  proxyPort,
		proxy:      proxy,
		cmd:        cmd,
		logFile:    logFile,
		done:       done,
	}

	if err := c.waitForAgentSocket(node); err != nil {
		return nil, err
	}
	return node, nil
}

func (c *HACluster) waitForAgentSocket(node *haNode) error {
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := os.Stat(node.agentSock); err == nil {
			return nil
		}
		select {
		case err := <-node.done:
			return fmt.Errorf("controller exited before its agent socket appeared: %v\n%s", err, c.readLogTail(node.logFile))
		case <-time.After(200 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for agent socket %s (controller still running, pid %d)\n%s",
				node.agentSock, node.cmd.Process.Pid, c.readLogTail(node.logFile))
		}
	}
}

func (c *HACluster) readLogTail(f *os.File) string {
	data, err := os.ReadFile(f.Name())
	if err != nil {
		return fmt.Sprintf("(could not read log: %v)", err)
	}
	if len(data) > 4096 {
		data = data[len(data)-4096:]
	}
	return string(data)
}

func (c *HACluster) execAgentInit(node *haNode) error {
	cmd := exec.Command(c.ZitiBin, "agent", "cluster", "init",
		c.Username, c.Password, c.Username,
		"--app-addr", "unix:"+node.agentSock, "--timeout", "30s")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w\n%s", err, out)
	}
	return nil
}

// execAgentJoin joins node to the cluster via node 0's proxy address.
// Retries: joining can fail transiently while the target elects a leader,
// mirroring quickstart.go's own join retry loop.
func (c *HACluster) execAgentJoin(node *haNode) error {
	target := fmt.Sprintf("tls:localhost:%d", c.nodes[0].proxyPort)
	deadline := time.Now().Add(90 * time.Second)
	var lastErr error
	for attempt := 1; ; attempt++ {
		cmd := exec.Command(c.ZitiBin, "agent", "cluster", "add", target,
			"--app-addr", "unix:"+node.agentSock, "--timeout", "15s")
		out, err := cmd.CombinedOutput()
		if err == nil {
			return nil
		}
		lastErr = fmt.Errorf("%w\n%s", err, out)
		if time.Now().After(deadline) {
			return fmt.Errorf("join timed out after %d attempt(s): %w", attempt, lastErr)
		}
		time.Sleep(2 * time.Second)
	}
}

// WaitForClusterLeader blocks until the cluster has elected a leader.
func (c *HACluster) WaitForClusterLeader() error {
	return waitForClusterLeader(c.execZiti, "hacluster")
}

// WaitForDataModelConsensus blocks until every controller node reports the
// same data-model index - call after a data-model-mutating admin op (e.g.
// CreateIdentityJWT) and before anything that depends on every node seeing
// it, so a random controller pick doesn't race replication - the still-open,
// unrelated bug this is guarding against, not exercising
// (openziti/ziti-sdk-c#1134: a freshly-enrolled identity's first auth can
// land on a node that hasn't replicated it yet).
func (c *HACluster) WaitForDataModelConsensus() {
	waitForDataModelConsensus(c.execZiti, "hacluster", len(c.nodes))
}

// startRouter creates and enrolls one edge router via node 0's proxy, then
// starts it - mirroring quickstart.go's own configureRouter/runRouter as
// plain CLI calls. The router's own address is not proxied (see type doc).
func (c *HACluster) startRouter(t *testing.T) error {
	t.Helper()
	c.routerName = "hacluster-router"
	jwtPath := filepath.Join(c.Home, c.routerName+".jwt")
	if _, err := c.execZiti("edge create edge-router %s %s --tunneler-enabled --role-attributes=public",
		c.routerName, fmt.Sprintf("--jwt-output-file=%s", jwtPath)); err != nil {
		return fmt.Errorf("create edge-router: %w", err)
	}

	configPath := filepath.Join(c.Home, c.routerName+".yaml")
	createCfgCmd := exec.Command(c.ZitiBin, "create", "config", "router", "edge",
		"--routerName", c.routerName, "--output", configPath)
	createCfgCmd.Env = append(os.Environ(),
		"ZITI_HOME="+c.Home,
		"ZITI_CTRL_ADVERTISED_ADDRESS=localhost",
		fmt.Sprintf("ZITI_CTRL_ADVERTISED_PORT=%d", c.nodes[0].proxyPort),
		"ZITI_CTRL_EDGE_ADVERTISED_ADDRESS=localhost",
		fmt.Sprintf("ZITI_CTRL_EDGE_ADVERTISED_PORT=%d", c.nodes[0].proxyPort),
		"ZITI_ROUTER_ADVERTISED_ADDRESS=localhost",
		fmt.Sprintf("ZITI_ROUTER_PORT=%d", c.RouterPort),
	)
	if out, err := createCfgCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("create router config: %w\n%s", err, out)
	}

	if _, err := c.execZiti("router enroll %s %s", configPath, fmt.Sprintf("--jwt=%s", jwtPath)); err != nil {
		return fmt.Errorf("enroll router: %w", err)
	}
	_ = os.Remove(jwtPath)

	logFile, err := os.OpenFile(filepath.Join(c.Home, c.routerName+".log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open router log: %w", err)
	}
	c.routerLog = logFile

	c.routerCmd = exec.Command(c.ZitiBin, "router", "run", configPath)
	if c.DetachSession {
		detachSession(c.routerCmd)
	}
	c.routerCmd.Stdout = logFile
	c.routerCmd.Stderr = logFile
	if err := c.routerCmd.Start(); err != nil {
		return fmt.Errorf("start router: %w", err)
	}
	c.routerDone = make(chan error, 1)
	go func() { c.routerDone <- c.routerCmd.Wait() }()

	return c.waitForRouterOnline()
}

// waitForRouterOnline mirrors Overlay.waitForRouterOnline: poll the
// controller's own view of the router (isOnline), not just whether its
// listener port is open - a port can accept TCP before the router has
// actually finished enrolling/connecting, and this is the same semantic
// signal the already-proven single-node path relies on.
func (c *HACluster) waitForRouterOnline() error {
	deadline := time.Now().Add(30 * time.Second)
	for {
		out, err := c.execZiti("edge list edge-routers -j")
		if err == nil {
			var resp struct {
				Data []struct {
					Name     string `json:"name"`
					IsOnline bool   `json:"isOnline"`
				} `json:"data"`
			}
			if json.Unmarshal(out, &resp) == nil {
				for _, router := range resp.Data {
					if router.Name == c.routerName && router.IsOnline {
						return nil
					}
				}
			}
		}
		select {
		case err := <-c.routerDone:
			return fmt.Errorf("router exited before coming online: %v", err)
		case <-time.After(500 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("router did not come online within 30s")
		}
	}
}

// CreateIdentityJWT provisions a new (non-admin) identity and returns its
// enrollment JWT content. Mirrors Overlay.CreateIdentityJWT.
func (c *HACluster) CreateIdentityJWT(name string) (string, error) {
	jwtPath := filepath.Join(c.Home, name+".jwt")
	if _, err := c.execZiti("edge create identity %s -o %s", name, jwtPath); err != nil {
		return "", fmt.Errorf("create identity %s: %w", name, err)
	}
	content, err := os.ReadFile(jwtPath)
	if err != nil {
		return "", fmt.Errorf("read jwt %s: %w", jwtPath, err)
	}
	return strings.TrimSpace(string(content)), nil
}

// Sever black-holes every controller node's proxy at once - see
// OutageProxy.Sever. The router is unaffected (see type doc).
func (c *HACluster) Sever() {
	for _, n := range c.nodes {
		n.proxy.Sever()
	}
}

// Restore ends the simulated outage on every controller node's proxy at once.
func (c *HACluster) Restore() {
	for _, n := range c.nodes {
		n.proxy.Restore()
	}
}

// Stop tears down every controller node, the router, and their proxies.
// Safe to call multiple times or on a cluster that never fully started.
func (c *HACluster) Stop() {
	if c.routerCmd != nil {
		relayStop(c.routerCmd)
	}
	for _, n := range c.nodes {
		if n != nil && n.cmd != nil {
			relayStop(n.cmd)
		}
	}
	if c.routerDone != nil {
		select {
		case <-c.routerDone:
		case <-time.After(30 * time.Second):
			log.Printf("hacluster: router did not exit within 30s of stop signal")
		}
	}
	for _, n := range c.nodes {
		if n == nil {
			continue
		}
		if n.done != nil {
			select {
			case <-n.done:
			case <-time.After(30 * time.Second):
				log.Printf("hacluster: node %s did not exit within 30s of stop signal", n.instanceID)
			}
		}
		if n.logFile != nil {
			_ = n.logFile.Close()
		}
	}
	if c.routerLog != nil {
		_ = c.routerLog.Close()
	}
}
