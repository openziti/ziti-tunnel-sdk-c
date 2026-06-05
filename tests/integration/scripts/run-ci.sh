#!/usr/bin/env bash
# Run the integration test suite end-to-end the same way CI does. Lets a
# local dev reproduce a CI failure with one command.
#
# Required input:
#   ZET_BIN  Absolute path to a built ziti-edge-tunnel binary.
#
# Optional input:
#   TEST_HOME      Working dir for overlay, logs, caches. Defaults to a temp dir.
#   ZITI_VERSION   ziti release tag to download (default: newest non-prerelease).
#   IDP_VERSION    dex version tag (default: fetch-dex.sh's pinned version).
#   ZET1_VERSION   If set, downloads this ZET release and uses it as ZET_BIN.
#   ZET2_VERSION   If set, downloads this ZET release and uses it as ZET_BIN_B.
#
# Flags:
#   --install-cert  Install the test overlay CA into OS trust for the run and
#                   remove it on exit. Off by default so the script does not
#                   mutate a normal user's trust store.
#
# Requires:  go, gh, jq, sudo (Linux/macOS).

set -euxo pipefail

INSTALL_CERT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --install-cert) INSTALL_CERT=1 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
  shift
done

: "${ZET_BIN:?ZET_BIN must point to a ziti-edge-tunnel binary}"

if [ ! -x "$ZET_BIN" ]; then
  echo "ZET_BIN=$ZET_BIN is not executable" >&2
  exit 1
fi

for tool in go gh jq curl unzip; do
  command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 1; }
done

# On macOS CI: disable Spotlight and evict unnecessary GUI/widget daemons.
# These collectively consume ~400 MB that we need for the test run.
# launchctl bootout removes the service from the current login session so
# launchd will not relaunch it (unlike `launchctl stop` which allows relaunch).
if [[ "$(uname -s)" == Darwin ]]; then
  sudo mdutil -a -i off 2>/dev/null || true
  _uid=$(id -u)
  launchctl list 2>/dev/null \
    | awk 'NR>1 && $3!="" {print $3}' \
    | grep -iE '(weather|stocks|news|noticeboard|siriinfer|safari.*(bookmark|link|widget)|nsattributedstring|cachedelete)' \
    | while IFS= read -r _label; do
        launchctl bootout "gui/$_uid/$_label" 2>/dev/null || true
      done
  # Widget extensions (WeatherWidget, StocksWidget, NewsToday2, etc.) are app
  # extensions hosted by the Dock, not individual launchd services. Restarting
  # the Dock evicts them; it relaunches itself immediately but starts clean.
  launchctl bootout "gui/$_uid/com.apple.Dock.agent" 2>/dev/null || true
  unset _uid
fi

# macOS does not ship timeout(1); define a minimal stand-in.
if ! command -v timeout >/dev/null 2>&1; then
  timeout() {
    local secs=$1; shift
    "$@" &
    local pid=$!
    ( sleep "$secs" && kill "$pid" 2>/dev/null ) &
    local wd=$!
    wait "$pid" 2>/dev/null
    local rc=$?
    kill "$wd" 2>/dev/null
    wait "$wd" 2>/dev/null
    return $rc
  }
fi

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)   ZITI_PATTERN="ziti-linux-amd64-*.tar.gz"; ZET_ZIP="ziti-edge-tunnel-Linux_x86_64.zip";  ZET_BIN_NAME="ziti-edge-tunnel" ;;
  Darwin-arm64)   ZITI_PATTERN="ziti-darwin-arm64-*.tar.gz"; ZET_ZIP="ziti-edge-tunnel-Darwin_arm64.zip"; ZET_BIN_NAME="ziti-edge-tunnel" ;;
  Darwin-x86_64)  ZITI_PATTERN="ziti-darwin-amd64-*.tar.gz"; ZET_ZIP="ziti-edge-tunnel-Darwin_x86_64.zip"; ZET_BIN_NAME="ziti-edge-tunnel" ;;
  *) echo "unsupported os/arch: $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac

TEST_HOME="${TEST_HOME:-$(mktemp -d -t ziti-tunnel-test.XXXXXX)}"
mkdir -p "$TEST_HOME"
echo "TEST_HOME=$TEST_HOME"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

# ---- Resolve ziti version ----------------------------------------------------
if [ -z "${ZITI_VERSION:-}" ]; then
  ZITI_VERSION=$(gh release list --repo openziti/ziti --limit 50 \
    --json tagName,isDraft,isPrerelease \
    | jq -r '.[] | select(.isDraft==false and .isPrerelease==false) | .tagName' \
    | sort -V | tail -n1)
fi
echo "Using ziti $ZITI_VERSION"

# ---- Download ziti CLI -------------------------------------------------------
ZITI_DIR="$TEST_HOME/ziti-cli"
mkdir -p "$ZITI_DIR"
(
  cd "$ZITI_DIR"
  gh release download --repo openziti/ziti "$ZITI_VERSION" --pattern "$ZITI_PATTERN" --clobber
  for archive in *.tar.gz; do [ -e "$archive" ] && tar -xzf "$archive"; done
)
ZITI_BIN=$(find "$ZITI_DIR" -type f -name ziti | head -n1)
chmod +x "$ZITI_BIN"
echo "ZITI_BIN=$ZITI_BIN"

# ---- Build/fetch dex ---------------------------------------------------------
DEX_DIR="$TEST_HOME/dex"
[ -n "${IDP_VERSION:-}" ] && export VERSION="$IDP_VERSION"
DEST="$DEX_DIR" "$REPO_ROOT/tests/integration/scripts/fetch-dex.sh"
IDP_BIN="$DEX_DIR/dex"
echo "IDP_BIN=$IDP_BIN"

# ---- Optional ZET release overrides ------------------------------------------
ZET_BIN_B="${ZET_BIN_B:-$ZET_BIN}"
if [ -n "${ZET1_VERSION:-}" ]; then
  d="$TEST_HOME/zet1"; mkdir -p "$d"
  (cd "$d" && gh release download --repo openziti/ziti-tunnel-sdk-c "$ZET1_VERSION" --pattern "$ZET_ZIP" --clobber && unzip -o "$ZET_ZIP")
  ZET_BIN="$d/$ZET_BIN_NAME"
  chmod +x "$ZET_BIN"
fi
if [ -n "${ZET2_VERSION:-}" ]; then
  d="$TEST_HOME/zet2"; mkdir -p "$d"
  (cd "$d" && gh release download --repo openziti/ziti-tunnel-sdk-c "$ZET2_VERSION" --pattern "$ZET_ZIP" --clobber && unzip -o "$ZET_ZIP")
  ZET_BIN_B="$d/$ZET_BIN_NAME"
  chmod +x "$ZET_BIN_B"
fi
echo "ZET_BIN=$ZET_BIN"
echo "ZET_BIN_B=$ZET_BIN_B"

# ---- Heartbeat monitor -------------------------------------------------------
# Periodically logs memory pressure, top processes by RSS, DNS config, and
# GitHub reachability. Started early so setup failures are also captured.
# This survives a runner-agent death so we can tell whether the macOS
# "runner lost communication" failure is OOM or CPU starvation.
(
  set +ex  # don't exit on failure; suppress xtrace noise in log
  while true; do
    sleep 10
    echo "=== heartbeat $(date) ==="
    case "$(uname -s)" in
      Darwin)
        echo "routes:"
        netstat -rn -finet
        echo "dns config:"
        scutil --dns 2>/dev/null
        echo "dns resolution:"
        nslookup api.github.com 2>/dev/null || dig +short api.github.com 2>/dev/null || true
        echo "vm_stat:"
        vm_stat | awk 'NR==1 || /Pages (free|active|wired down|occupied by compressor):/ {print}'
        echo ""
        echo "memory_pressure:"
        memory_pressure 2>/dev/null | tail -1 || true
        echo ""
        echo "top memory consumers:"
        printf "%-8s %8s %6s  %s\n" "PID" "RSS(MB)" "%CPU" "COMMAND"
        ps axo pid=,rss=,pcpu=,comm= | sort -k2 -rn 2>/dev/null | head -20 \
          | awk '{printf "%-8s %8.1f %6s  %s\n", $1, $2/1024, $3, $4}' || true
        echo ""
        ;;
      Linux)
        free -m | grep -E '^(Mem|Swap):'
        echo "top memory consumers:"
        printf "%-8s %8s %6s  %s\n" "PID" "RSS(MB)" "%CPU" "COMMAND"
        ps axo pid=,rss=,pcpu=,comm= --sort=-rss | head -20 \
          | awk '{printf "%-8s %8.1f %6s  %s\n", $1, $2/1024, $3, $4}' || true
        ;;
    esac
    curl -sf --max-time 5 https://api.github.com >/dev/null \
      && echo "github reachable" \
      || echo "GITHUB UNREACHABLE"
    echo "tunnel_status zetA:"
    timeout 8 sudo "$ZET_BIN" tunnel_status -P zetA 2>&1 || true
    echo "tunnel_status zetB:"
    timeout 8 sudo "$ZET_BIN" tunnel_status -P zetB 2>&1 || true
  done
) &
HEARTBEAT_PID=$!

# ---- Jetsam / OOM watcher (macOS only) --------------------------------------
# Streams system log entries about process kills and memory pressure events in
# real time. If the runner agent or test binary is killed by jetsam these lines
# will appear in the job log immediately before or after output goes dark.
JETSAM_PID=""
if [[ "$(uname -s)" == Darwin ]]; then
  ( log stream \
      --predicate 'eventMessage CONTAINS "jetsam" OR eventMessage CONTAINS "low memory" OR eventMessage CONTAINS "killed process" OR eventMessage CONTAINS "memorystatus"' \
      --style compact 2>/dev/null \
    | sed 's/^/[jetsam] /' ) &
  JETSAM_PID=$!
fi

# ---- Create ziti group + configure core dumps --------------------------------
case "$(uname -s)" in
  Linux)
    sudo groupadd --system ziti 2>/dev/null || true
    sudo mkdir -p /tmp/cores
    sudo chmod 1777 /tmp/cores
    echo '/tmp/cores/core.%e.%p' | sudo tee /proc/sys/kernel/core_pattern >/dev/null
    echo 1 | sudo tee /proc/sys/fs/suid_dumpable >/dev/null
    ;;
  Darwin)
    sudo dseditgroup -o create ziti 2>/dev/null || true
    sudo mkdir -p /cores
    sudo chmod 1777 /cores
    sudo sysctl -w kern.corefile='/cores/core.%N.%P' >/dev/null
    ;;
esac

# ---- Seed test overlay PKI ---------------------------------------------------
# Seed at $TEST_HOME/overlay (where the test framework's own quickstart runs)
# so its second quickstart reuses this PKI, ensuring the cert we install into
# OS trust matches the cert the test's controller serves.
OVERLAY_HOME="$TEST_HOME/overlay"
echo "Seeding test overlay PKI at $OVERLAY_HOME"
"$ZITI_BIN" edge quickstart --home="$OVERLAY_HOME" \
  --ctrl-address=localhost --ctrl-port=1280 \
  --router-address=localhost --router-port=3022 &
QS_PID=$!
SECONDS=0
until curl -sk --max-time 2 https://localhost:1280/ >/dev/null \
   && (echo > /dev/tcp/localhost/3022) 2>/dev/null; do
  if (( SECONDS > 120 )); then
    kill "$QS_PID" 2>/dev/null || true
    echo "overlay never came up within 120s" >&2
    exit 1
  fi
  sleep 1
done
kill "$QS_PID"
wait "$QS_PID" 2>/dev/null || true

# ---- CA trust ------------------------------------------------------------------
# The harness installs the overlay CA into OS trust after the fixture import and
# removes it at teardown when ziti.autoTrustCa is set.
if [ -z "$INSTALL_CERT" ]; then
  echo "WARNING: autoTrustCa disabled (pass --install-cert to enable); tests that require the controller cert to be trusted may fail" >&2
  AUTO_TRUST_CA=false
else
  AUTO_TRUST_CA=true
fi

# ---- Write config.json -------------------------------------------------------
cd "$REPO_ROOT/tests/integration"
jq -n \
  --arg testHome "$TEST_HOME" \
  --arg zitiBin  "$ZITI_BIN" \
  --arg zetBin   "$ZET_BIN" \
  --arg zetBinB  "$ZET_BIN_B" \
  --arg idpBin   "$IDP_BIN" \
  --argjson autoTrustCa "$AUTO_TRUST_CA" \
  '{
    testHome: $testHome,
    ziti: { binary: $zitiBin, url: "", user: "admin", password: "admin", autoTrustCa: $autoTrustCa },
    zetA: { binary: $zetBin,  verbosity: 4, tlsuvDebug: 0 },
    zetB: { binary: $zetBinB, verbosity: 4, tlsuvDebug: 0 },
    idp: {
      useTestHarnessIdP: true,
      binary: $idpBin,
      issuer: "",
      clientId: "ziti-test",
      extraClientIds: ["ziti-test-2", "ziti-test-3"],
      audience: "ziti-test",
      scopes: "openid profile email",
      password: "password"
    }
  }' > config.json
cat config.json

# ---- Compile test binary -----------------------------------------------------
# Compile as the current (non-root) user so the Go module and build cache are
# accessible. sudo resets HOME/GOPATH/GOCACHE, so `go test` as root re-downloads
# all modules and recompiles from scratch — exhausting memory on constrained CI
# runners (observed as a 100% reproducible "runner lost communication" on macOS).
INTEGRATION_TEST="$TEST_HOME/integration.test"
go test -c -o "$INTEGRATION_TEST" .

# ---- Run tests ---------------------------------------------------------------
# sudo resets PAM resource limits, so ulimit must be set in the privileged shell.
sudo env "PATH=$PATH" "INTEGRATION_TEST=$INTEGRATION_TEST" sh -c \
  'ulimit -c unlimited && exec "$INTEGRATION_TEST" -test.v -test.timeout 20m -config config.json'

