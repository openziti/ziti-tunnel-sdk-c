#!/usr/bin/env bash
set -euo pipefail

_usage(){
    cat <<-EOF
Usage: VARIABLES ./buildx.sh [OPTION]...

Build multi-platform Docker container image on Linux.

VARIABLES
    ZITI_VERSION      e.g. "0.16.1" corresponding to Git tag "v0.16.1"

OPTIONS
    -c                don't check out v\${ZITI_VERSION} (use Git working copy)

EXAMPLES
    ZITI_VERSION=0.16.1 ./buildx.sh -c

REFERENCE
    https://github.com/openziti/ziti-tunnel-sdk-c/blob/main/docker/BUILD.md
EOF
    [[ $# -eq 1 ]] && {
        return $1
    } || {
        return 0
    }
}

# default to latest
: ${ZITI_VERSION:=$(git fetch --tags && git tag -l|sort -Vr|head -1|sed -E 's/^v(.*)/\1/')}
BASENAME=$(basename $0) || exit $?
DIRNAME=$(dirname $0) || exit $?

while getopts :c OPT;do
  case $OPT in
	c) 	FLAGS+=$OPT ;; # don't checkout vZITI_VERSION
    *|\?|h) _usage;exit
			;;
  esac
done
shift "$((OPTIND-1))"

if [[ ${FLAGS:-} =~ c ]]; then
    echo "WARN: not checking out Git tag v${ZITI_VERSION}"
else
    git diff --exit-code # bail if unstaged differences
    git fetch --tags
    git co v${ZITI_VERSION}
fi

docker run --rm --privileged docker/binfmt:a7996909642ee92942dcd6cff44b9b95f08dad64
egrep -q enabled /proc/sys/fs/binfmt_misc/qemu-arm
docker run --rm arm64v8/alpine uname -a|egrep -q 'aarch64 Linux'
docker run --rm arm32v7/alpine uname -a|egrep -q 'armv7l Linux'

docker buildx create --use --name=ziti-builder 2>/dev/null || docker buildx use --default ziti-builder

cd $DIRNAME             # ensure ziti-tunnel-sdk-c/docker/Dockerfile is in PWD
docker buildx build . \
    --platform linux/amd64,linux/arm/v7,linux/arm64 \
    --build-arg ZITI_VERSION=${ZITI_VERSION} \
    --tag netfoundry/ziti-edge-tunnel:${ZITI_VERSION} \
    --tag netfoundry/ziti-edge-tunnel:latest \
    --push

docker buildx stop ziti-builder
