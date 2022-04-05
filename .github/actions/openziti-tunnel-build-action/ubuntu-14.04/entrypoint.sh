#!/usr/bin/env bash
#
# Ubuntu Trusty 14.04
#

set -euo pipefail

# these commands must be in the entrypoint so they are run after workspace is mounted on Docker workdir
echo "INFO: GIT_DISCOVERY_ACROSS_FILESYSTEM=${GIT_DISCOVERY_ACROSS_FILESYSTEM}"
echo "INFO: WORKDIR=${PWD}"
echo "INFO: $(git --version)"

cmake -E make_directory ./build  
cmake \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_TOOLCHAIN_FILE=./toolchains/default.cmake \
    -DBUILD_DIST_PACKAGES=ON \
    -DDISABLE_LIBSYSTEMD_FEATURE=ON \
    -S . \
    -B ./build 
cmake \
    --build ./build \
    --target package \
    --verbose

if (( ${#} )); then
    echo "INFO: running ziti-edge-tunnel"
    set -x
    ./build/programs/ziti-edge-tunnel/ziti-edge-tunnel ${@}
fi
