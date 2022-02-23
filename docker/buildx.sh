#!/usr/bin/env bash
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

_usage(){
    cat >&2 <<-EOF
Usage: VARIABLES ./buildx.sh [OPTION]...

Build multi-platform Docker container image on Linux.

VARIABLES
    ZITI_VERSION      e.g. "0.16.1" corresponding to Git tag "v0.16.1"

OPTIONS
    -r REPO           container image repository e.g. netfoundry/ziti-edge-tunnel
    -c                don't check out v\${ZITI_VERSION} (use Git working copy)
    -l                additionally tag ziti-edge-tunnel:latest
    -f                clobber Docker registry tag if it exists


EXAMPLES
    ZITI_VERSION=0.16.1 ./buildx.sh -c

REFERENCE
    https://github.com/openziti/ziti-tunnel-sdk-c/blob/main/docker/BUILD.md
EOF
    if [[ $# -eq 1 ]]; then
        return "$1"
    else
        return 0
    fi
}

#BASENAME=$(basename $0) || exit $?
DIRNAME=$(dirname "$0") || exit $?
EXIT=0

while getopts :r:chlf OPT;do
    case $OPT in
        r)  CONTAINER_REPO=$OPTARG 
            ;;
        c) 	FLAGS+=$OPT     # don't checkout vZITI_VERSION
            ;;
        h) _usage; exit 0   # not an error
            ;;
        l)  FLAGS+=$OPT     # also tag and push latest
            ;;
        f)  FLAGS+=$OPT
            ;;
        \?|*) _usage 1      # error
            ;;
    esac
done
shift "$((OPTIND-1))"

# default to latest
: "${ZITI_VERSION:=$(git fetch --quiet --tags && git tag -l|sort -Vr|head -1|sed -E 's/^v(.*)/\1/')}"

# required opts
if [[ -z "${CONTAINER_REPO:-}" ]]; then
    echo "ERROR: missing -r REPO option to define container image repository name for image push" >&2
    _usage; exit 1
else
    TAG_PARAMS="--tag=\"${CONTAINER_REPO}:${ZITI_VERSION}\""
fi

if [[ ${FLAGS:-} =~ c ]]; then
    echo "WARN: not checking out Git tag v${ZITI_VERSION}"
else
    git diff --exit-code # bail if unstaged differences
    git fetch --tags
    git checkout "v${ZITI_VERSION}"
fi

if [[ ${FLAGS:-} =~ l ]]; then
    TAG_PARAMS+=" --tag=\"${CONTAINER_REPO}:latest\""
fi

docker run --rm --privileged docker/binfmt:a7996909642ee92942dcd6cff44b9b95f08dad64
grep -E -q 'enabled' /proc/sys/fs/binfmt_misc/qemu-arm
docker run --rm --platform linux/arm64/v8 arm64v8/alpine uname -a | grep -Eq 'aarch64 Linux'
docker run --rm --platform linux/arm/v7 arm32v7/alpine uname -a | grep -Eq 'armv7l Linux'
docker buildx create --use --name=ziti-builder 2>/dev/null || docker buildx use --default ziti-builder

# if 
if [[ ${FLAGS:-} =~ f ]] || ! curl -sSLf https://registry.hub.docker.com/v2/repositories/netfoundry/ziti-edge-tunnel/tags/${ZITI_VERSION} &>/dev/null; then
    eval docker buildx build "${DIRNAME}" \
        --platform="linux/amd64,linux/arm/v7,linux/arm64" \
        --build-arg=ZITI_VERSION="${ZITI_VERSION}" \
        "${TAG_PARAMS}" \
        --push
else
    echo "ERROR: Docker tag ziti-edge-tunnel:${ZITI_VERSION} already exists. Carefully send option -f to clobber Docker image tag." >&2
    EXIT=1
fi
docker buildx stop ziti-builder

exit $EXIT