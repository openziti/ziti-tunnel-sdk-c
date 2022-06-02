#!/usr/bin/env bash
#
# RedHat 7
#

set -euo pipefail

# these commands must be in the entrypoint so they are run after workspace is mounted on Docker workdir
echo "INFO: GIT_DISCOVERY_ACROSS_FILESYSTEM=${GIT_DISCOVERY_ACROSS_FILESYSTEM}"
echo "INFO: WORKDIR=${PWD}"
echo "INFO: $(git --version)"

# workspace dir for each build env is added to "safe" dirs in global config e.g.
# ~/.gitconfig so both runner and builder containers trust these dirs
# owned by different UIDs from that of Git's EUID. This is made necessary
# by newly-enforced directory boundaries in Git v2.35.2
# ref: https://lore.kernel.org/git/xmqqv8veb5i6.fsf@gitster.g/
for SAFE in \
    /github/workspace \
    /__w/ziti-tunnel-sdk-c/ziti-tunnel-sdk-c \
    /mnt ; do
        git config --global --add safe.directory ${SAFE}
done

cmake -E make_directory ./build
(
    # allow unset for scl_source scripts
    set +u
    cmake -E make_directory ./build  
    source scl_source enable devtoolset-11 \
        && cmake \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_TOOLCHAIN_FILE=./toolchains/default.cmake \
            -DBUILD_DIST_PACKAGES=ON \
            -DDISABLE_LIBSYSTEMD_FEATURE=ON \
            -S . \
            -B ./build
    source scl_source enable devtoolset-11 \
        && cmake \
            --build ./build \
            --target package \
            --verbose
)

if (( ${#} )); then
    echo "INFO: running ziti-edge-tunnel"
    set -x
    ./build/programs/ziti-edge-tunnel/ziti-edge-tunnel ${@}
fi
