#!/usr/bin/env bash
# Clone the dex source and build the dex binary.
# Dex doesn't publish prebuilt binaries, and its module path predates Go
# modules' /vN/ convention, which breaks 'go install ...@latest'. Cloning the
# tag and running 'go build' from the working tree is the supported path.
#
# Usage:
#   ./fetch-dex.sh                       # builds the version pinned below
#   VERSION=v2.45.1 ./fetch-dex.sh
#   DEST=/opt/dex ./fetch-dex.sh

set -euo pipefail

VERSION="${VERSION:-v2.45.1}"
FORCE="${FORCE:-}"

# Durable cache:
#   Linux:   $XDG_CACHE_HOME/ziti-tunnel-test-dex/<version>  (default ~/.cache)
#   macOS:   ~/Library/Caches/ziti-tunnel-test-dex/<version>
#   Windows: %LOCALAPPDATA%\ziti-tunnel-test-dex\<version>
if [[ -z "${DEST:-}" ]]; then
    case "$(uname -s)" in
        Darwin) cache_root="$HOME/Library/Caches" ;;
        MINGW*|MSYS*|CYGWIN*) cache_root="${LOCALAPPDATA:-$HOME/AppData/Local}" ;;
        *) cache_root="${XDG_CACHE_HOME:-$HOME/.cache}" ;;
    esac
    DEST="$cache_root/ziti-tunnel-test-dex/$VERSION"
fi

command -v go  >/dev/null 2>&1 || { echo "go is not on PATH -- install Go first" >&2; exit 1; }
command -v git >/dev/null 2>&1 || { echo "git is not on PATH"                    >&2; exit 1; }

mkdir -p "$DEST"
src_dir="$DEST/src"

case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) bin_name="dex.exe" ;;
    *) bin_name="dex" ;;
esac
dex_bin="$DEST/$bin_name"

if [[ -x "$dex_bin" && -z "$FORCE" ]]; then
    echo "dex already built at $dex_bin (set FORCE=1 to rebuild)"
    exit 0
fi

if [[ -d "$src_dir" ]]; then
    echo "removing stale clone at $src_dir"
    rm -rf "$src_dir"
fi

echo "cloning dex $VERSION into $src_dir"
git clone --depth 1 --branch "$VERSION" https://github.com/dexidp/dex.git "$src_dir"

echo "building $bin_name -> $dex_bin"
(
    cd "$src_dir"
    # Force auto-toolchain so Go downloads whatever version dex's go.mod requires.
    GOTOOLCHAIN=auto go build -o "$dex_bin" ./cmd/dex
)

echo
echo "dex binary: $dex_bin"
