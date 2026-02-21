#!/usr/bin/env nix-shell
#! nix-shell -i bash -p curl jq nix-prefetch-github

# Update script for the Nix package of ziti-edge-tunnel.
#
# Usage:
#   ./nix/update.sh          # update to latest release
#   ./nix/update.sh v1.11.0  # update to a specific tag
#
# Requires: nix-shell (pulls in curl, jq, nix-prefetch-github automatically)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_FILE="$SCRIPT_DIR/packages/ziti-edge-tunnel.nix"

gh_api() {
  local url="$1"
  curl -fsSL -H "Accept: application/vnd.github+json" \
    ${GITHUB_TOKEN:+-H "Authorization: Bearer $GITHUB_TOKEN"} \
    "https://api.github.com/$url"
}

gh_raw() {
  local owner="$1" repo="$2" ref="$3" path="$4"
  curl -fsSL "https://raw.githubusercontent.com/$owner/$repo/$ref/$path"
}

prefetch() {
  local owner="$1" repo="$2" rev="$3"
  nix-prefetch-github "$owner" "$repo" --rev "$rev" --json 2>/dev/null |
    jq -r '.hash'
}

update_field() {
  local file="$1" marker="$2" field="$3" value="$4"
  python3 -c "
import re, sys

text = open('$file').read()
mi = text.find('$marker')
if mi == -1:
    print('WARNING: marker \"$marker\" not found in $file', file=sys.stderr)
    sys.exit(0)
pattern = re.compile(r'($field\s*=\s*)\"[^\"]*\"')
m = pattern.search(text, mi)
if m:
    text = text[:m.start()] + m.group(1) + '\"$value\"' + text[m.end():]
    open('$file', 'w').write(text)
    print('  $field -> $value')
else:
    print('WARNING: field \"$field\" not found after \"$marker\"', file=sys.stderr)
" 2>&1
}

echo "==> Determining ziti-tunnel-sdk-c version..."
if [ -n "${1:-}" ]; then
  TUNNEL_TAG="$1"
else
  TUNNEL_TAG=$(gh_api "repos/openziti/ziti-tunnel-sdk-c/releases/latest" | jq -r '.tag_name')
fi
TUNNEL_VERSION="${TUNNEL_TAG#v}"
echo "    ziti-tunnel-sdk-c: $TUNNEL_VERSION"

echo "==> Reading ZITI_SDK_VERSION from CMakeLists.txt..."
SDK_VERSION=$(gh_raw openziti ziti-tunnel-sdk-c "$TUNNEL_TAG" CMakeLists.txt |
  grep -oP 'set\(ZITI_SDK_VERSION\s+"\K[^"]+')
echo "    ziti-sdk-c: $SDK_VERSION"

echo "==> Reading tlsuv version from ziti-sdk-c..."
TLSUV_VERSION=$(gh_raw openziti ziti-sdk-c "$SDK_VERSION" CMakeLists.txt |
  grep -oP 'set\(tlsuv_VERSION\s+"\K[^"]+')
echo "    tlsuv: $TLSUV_VERSION"

echo "==> Getting latest subcommands.c commit..."
SUBCOMMAND_REV=$(gh_api "repos/openziti/subcommands.c/commits/main" | jq -r '.sha')
echo "    subcommands.c: ${SUBCOMMAND_REV:0:12}"

echo ""
echo "==> Prefetching sources (this may take a minute)..."

echo "  ziti-tunnel-sdk-c $TUNNEL_TAG..."
TUNNEL_HASH=$(prefetch openziti ziti-tunnel-sdk-c "$TUNNEL_TAG")
echo "    $TUNNEL_HASH"

echo "  ziti-sdk-c $SDK_VERSION..."
SDK_HASH=$(prefetch openziti ziti-sdk-c "$SDK_VERSION")
echo "    $SDK_HASH"

echo "  tlsuv $TLSUV_VERSION..."
TLSUV_HASH=$(prefetch openziti tlsuv "$TLSUV_VERSION")
echo "    $TLSUV_HASH"

echo "  subcommands.c ${SUBCOMMAND_REV:0:12}..."
SUBCOMMAND_HASH=$(prefetch openziti subcommands.c "$SUBCOMMAND_REV")
echo "    $SUBCOMMAND_HASH"

echo ""
echo "==> Updating $PKG_FILE"

# Main package version
update_field "$PKG_FILE" 'pname = "ziti-edge-tunnel"' "version" "$TUNNEL_VERSION"

# Main source hash
update_field "$PKG_FILE" 'repo = "ziti-tunnel-sdk-c"' "hash" "$TUNNEL_HASH"

# ziti-sdk-c
update_field "$PKG_FILE" 'repo = "ziti-sdk-c"' "tag" "$SDK_VERSION"
update_field "$PKG_FILE" 'repo = "ziti-sdk-c"' "hash" "$SDK_HASH"

# tlsuv
update_field "$PKG_FILE" 'repo = "tlsuv"' "tag" "$TLSUV_VERSION"
update_field "$PKG_FILE" 'repo = "tlsuv"' "hash" "$TLSUV_HASH"

# subcommands.c
update_field "$PKG_FILE" 'repo = "subcommands.c"' "rev" "$SUBCOMMAND_REV"
update_field "$PKG_FILE" 'repo = "subcommands.c"' "hash" "$SUBCOMMAND_HASH"

echo ""
echo "==> Done! Updated to ziti-edge-tunnel $TUNNEL_VERSION"
echo "    Run 'nix build' to verify the build."
