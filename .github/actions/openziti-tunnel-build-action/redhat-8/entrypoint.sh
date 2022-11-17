#!/usr/bin/env bash
#
# RedHat 8
#

set -euo pipefail

# these commands must be in the entrypoint so they are run after workspace is mounted on Docker workdir
echo "INFO: GIT_DISCOVERY_ACROSS_FILESYSTEM=${GIT_DISCOVERY_ACROSS_FILESYSTEM}"
echo "INFO: WORKDIR=${PWD}"
echo "INFO: $(git --version)"

# if first positional is an expected arch string then set toolchain file, else default toolchain
if (( ${#} )); then
    case ${1} in
        amd64)  CMAKE_TOOLCHAIN_FILE="default.cmake"
                shift
        ;;
        arm64)  CMAKE_TOOLCHAIN_FILE="Linux-arm64.cmake"
                shift
        ;;
        arm)    CMAKE_TOOLCHAIN_FILE="Linux-arm.cmake"
                shift
        ;;
        *)      CMAKE_TOOLCHAIN_FILE="default.cmake"
        ;;
    esac
else
    CMAKE_TOOLCHAIN_FILE="default.cmake"
fi

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
    [[ -d ./build ]] && rm -r ./build
    cmake -E make_directory ./build  
    # allow unset for scl_source scripts
    set +u
    source scl_source enable gcc-toolset-10 \
        && cmake \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_TOOLCHAIN_FILE=./toolchains/${CMAKE_TOOLCHAIN_FILE} \
            -DBUILD_DIST_PACKAGES=ON \
            -DUSE_OPENSSL=ON \
            -S . \
            -B ./build 
    source scl_source enable gcc-toolset-10 \
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
