#!/bin/bash -eu
set -o pipefail

echo "Fetching from GitHub."
if [ -z "${GITHUB_BASE_URL}" ]; then GITHUB_BASE_URL="https://github.com/openziti"; fi
if [ -z "${GITHUB_REPO}" ]; then  GITHUB_REPO="ziti-tunnel-sdk-c"; fi
for var in GITHUB_BASE_URL GITHUB_REPO ZITI_VERSION; do
    if [ -z "${!var}" ]; then
        echo "ERROR: ${var} must be set when fetching binaries from GitHub." >&2
        exit 1
    fi
done

# map host architecture/os to directories that we use in GitHub.
# (our artifact directories seem to align with Docker's TARGETARCH and TARGETOS
#  build arguments, which we could rely on if we fully committed to "docker buildx" - see
#  https://docs.docker.com/engine/reference/builder/#automatic-platform-args-in-the-global-scope)
host_arch=$(uname -m)
case "${host_arch}" in
"x86_64") artifact_arch="x86_64";;
"armv7l"|"aarch64") artifact_arch="arm";;
*) echo "ERROR: Ziti binaries do not exist for architecture ${host_arch}"; exit 1;;
esac

host_os=$(uname -s)
case "${host_os}" in
"Linux") artifact_os="Linux";;
"Darwin") artifact_os="Darwin";;
#"Windows") artifact_os="windows";; # Windows bins do not exist
*) echo "ERROR: ziti binaries do not exist for os ${host_os}"; exit 1;;
esac

for exe in "${@}"; do
    zip="${exe}-${artifact_os}_${artifact_arch}.zip"
    url="${GITHUB_BASE_URL}/${GITHUB_REPO}/releases/download/v${ZITI_VERSION}/${zip}"
    echo "Fetching ${zip} from ${url}"
    rm -f "${zip}" "${exe}"
    if { command -v curl > /dev/null; } 2>&1; then
        curl -fLsS -O "${url}"
    elif { command -v wget > /dev/null; } 2>&1; then
        wget "${url}"
    else
        echo "ERROR: need one of curl or wget to fetch the artifact." >&2
        exit 1
    fi
    unzip "${zip}"
    if [ -f "${exe}" ]; then 
        chmod 755 "${exe}"
    elif [ -f "${exe}.exe" ]; then 
        chmod 755 "${exe}.exe"
    fi
    rm -f "${zip}"
done
