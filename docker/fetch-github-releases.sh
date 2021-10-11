#!/bin/bash

#
# Copyright 2021 NetFoundry Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

set -euo pipefail

[[ $# -eq 0 ]] && {
    echo "ERROR: need the base name of the executable to fetch e.g. \"ziti-edge-tunnel\"." >&2
    exit 1
}

echo "Fetching from GitHub."
# defaults
: "${GITHUB_BASE_URL:=https://github.com/openziti}"
: "${GITHUB_REPO:="ziti-tunnel-sdk-c"}"
: "${ZITI_VERSION:="latest"}"

if [[ "$ZITI_VERSION" == "latest" ]];then
    echo "WARN: ZITI_VERSION unspecified, using 'latest'" >&2
else
    # ensure version string begins with 'v' by stripping if present and re-adding
    ZITI_VERSION="v${ZITI_VERSION#v}"
fi

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
    url="${GITHUB_BASE_URL}/${GITHUB_REPO}/releases/download/${ZITI_VERSION}/${zip}"
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
