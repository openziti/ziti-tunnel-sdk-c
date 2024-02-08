#!/usr/bin/env bash

BASENAME="$(basename "${0}")"
BASEDIR="$(cd "$(dirname "${0}")" && pwd)"  # full path to scripts dir

if ! (( $# )) || [[ $* =~ -h|(--)?help ]]; then
    echo -e "\nUsage: ${BASENAME} [openssl|mbedtls] [x64|arm64|arm]"\
            "\n\nConfigures build preset for OpenSSL or Mbed-TLS and"\
            "\nbuilds the binary if ARCH is specified\n"
    exit 0
fi

set -euo pipefail;

function switch_tls(){
    local old=$1;
    local new=$2;
    # munge the preset to use openssl
    TMPFILE=$(mktemp);
    jq --arg old $old --arg new $new '.dependencies |= map(if . == $old then $new else . end)' ./vcpkg.json > "$TMPFILE";
    mv "$TMPFILE" ./vcpkg.json;
    
    jq --arg old $old --arg new $new \
    '.configurePresets |= map(
        if .cacheVariables.TLSUV_TLSLIB == $old then
            .cacheVariables.TLSUV_TLSLIB |= $new
        else
            .
        end
    )
    ' ./CMakePresets.json > "$TMPFILE";
    mv "$TMPFILE" ./CMakePresets.json;
}

TLSLIB=${1:-}
TARGETARCH=${2:-}

if [[ $TLSLIB == "mbedtls" ]]; then
    switch_tls "openssl" "mbedtls"
    PRESET="ci-linux-${TARGETARCH}"
elif [[ $TLSLIB == "openssl" ]]; then
    switch_tls "mbedtls" "openssl"
    PRESET="ci-linux-${TARGETARCH}-static-libssl"
else
    echo "Unknown TLS library: $TLSLIB"
    exit 1
fi

if [[ -z $TARGETARCH ]]; then
    echo "No architecture specified, only switching TLS library in vcpkg.json and CMakePresets.json"
    exit 0
elif [[ $TARGETARCH =~ ^(x64|arm(64))$ ]]; then
    "$BASEDIR/ziti-builder.sh" -p "$PRESET"
else
    echo "ERROR: Unknown architecture preset: $PRESET"
fi
