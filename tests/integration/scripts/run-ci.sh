#!/usr/bin/env bash
# Run the integration test suite end-to-end the same way CI does. Lets a
# local dev reproduce a CI failure with one command.
#
# Required input:
#   ZET_BIN   Absolute path to a ziti-edge-tunnel binary.
#   ZITI_BIN  Absolute path to a ziti binary. CI obtains it (a release or a main build).
#
# Optional input:
#   TEST_HOME      Working dir for overlay, logs, caches. Defaults to a temp dir.
#   IDP_VERSION    dex version tag (default: fetch-dex.sh's pinned version).
#   ZET_BIN_B      ziti-edge-tunnel binary for zetB. Defaults to ZET_BIN.
#
# Flags:
#   --install-cert  Install the test overlay CA into OS trust for the run and
#                   remove it on exit. Off by default so the script does not
#                   mutate a normal user's trust store.
#
# Requires:  go, jq, curl, and sudo (Linux/macOS).

set -euo pipefail

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

for tool in go jq curl; do
  command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 1; }
done

TEST_HOME="${TEST_HOME:-$(mktemp -d -t ziti-tunnel-test.XXXXXX)}"
mkdir -p "$TEST_HOME"
echo "TEST_HOME=$TEST_HOME"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

# ---- ziti CLI ----------------------------------------------------------------
: "${ZITI_BIN:?ZITI_BIN must point to a ziti binary}"
[ -x "$ZITI_BIN" ] || { echo "ZITI_BIN=$ZITI_BIN is not executable" >&2; exit 1; }
echo "ZITI_BIN=$ZITI_BIN"

# ---- Build/fetch dex ---------------------------------------------------------
DEX_DIR="$TEST_HOME/dex"
[ -n "${IDP_VERSION:-}" ] && export VERSION="$IDP_VERSION"
DEST="$DEX_DIR" "$REPO_ROOT/tests/integration/scripts/fetch-dex.sh"
IDP_BIN="$DEX_DIR/dex"
echo "IDP_BIN=$IDP_BIN"

ZET_BIN_B="${ZET_BIN_B:-$ZET_BIN}"
echo "ZET_BIN=$ZET_BIN"
echo "ZET_BIN_B=$ZET_BIN_B"

echo "ziti version: $("$ZITI_BIN" version)"
echo "zetA version: $("$ZET_BIN" version)"
echo "zetB version: $("$ZET_BIN_B" version)"
echo "dex version:  $("$IDP_BIN" version | head -1)"

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

# ---- Run tests ---------------------------------------------------------------
# sudo resets PAM resource limits, so ulimit must be set in the privileged shell.
sudo env "PATH=$PATH" sh -c \
  'ulimit -c unlimited && exec go test ./... -v -timeout 20m -config config.json'
