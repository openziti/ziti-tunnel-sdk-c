#!/usr/bin/env bash

BASENAME="$(basename "${0}")"
BASEDIR="$(cd "$(dirname "${0}")" && pwd)"  # full path to scripts dir

if [[ $* =~ -h|(--)?help ]]; then
    echo -e "\nUsage: ${BASENAME} [x64|arm64|arm]"\
            "\n\nConfigures build preset for OpenSSL and"\
            "\nbuilds the x86_64 target if no ARCH is specified\n"
    exit 0
fi

set -euxo pipefail;
TMPFILE=$(mktemp);

# munge the preset to use openssl
jq '.dependencies |= map(if . == "mbedtls" then "openssl" else . end)' ./vcpkg.json > "$TMPFILE";
mv "$TMPFILE" ./vcpkg.json;

jq '.configurePresets |= map(
    if .cacheVariables.TLSUV_TLSLIB == "mbedtls" then 
        .cacheVariables.TLSUV_TLSLIB |= "openssl" 
    else 
        . 
    end
)
' ./CMakePresets.json > "$TMPFILE";
mv "$TMPFILE" ./CMakePresets.json;

$BASEDIR/ziti-builder.sh -p ci-linux-${1:-x64}-static-libssl
