#!/usr/bin/env bash
#
# Debian Bullseye/Ubuntu Focal 20.04
#

set -euo pipefail

# these commands must be in the entrypoint so they are run after workspace is mounted on Docker workdir
echo "INFO: GIT_DISCOVERY_ACROSS_FILESYSTEM=${GIT_DISCOVERY_ACROSS_FILESYSTEM}"
echo "INFO: WORKDIR=${PWD}"
echo "INFO: $(git --version)"

# if first positional is an expected arch string then set cmake preset,
# else use ci-linux-x64 (which actually just uses native/host tools - e.g. not cross compile)
if [ ${#} -ge 1 ]; then
    cmake_preset="${1}"
else
    cmake_preset="ci-linux-x64"
fi

if [ ${#} -ge 2 ]; then
    cmake_config="${2}"
else
    cmake_config="Release"
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

[[ -d ./build ]] && rm -r ./build
cmake \
    -E make_directory \
    ./build/
cmake \
    --preset "${cmake_preset}" \
    -DCMAKE_BUILD_TYPE="${cmake_config}" \
    -DBUILD_DIST_PACKAGES=ON \
    -DUSE_OPENSSL=ON \
    -S "${PWD}/" \
    -B ./build/
cmake \
    --build ./build/ \
    --config "${cmake_config}" \
    --target package \
    --verbose

# The original idea behind that was to crudely test the built artifact inside
# the container image with the correct architecture before returning to allow
# the build job to succeed. Basically a smoke test to see if it would execute as
# built at all. I don't recall why I/we abandoned that idea in favor of only
# running the x86 artifact in the job container. So, we're not getting any value
# from those lines of the entrypoint scripts right now, and I agree we'd have to
# embellish the option parsing a bit to get that working.
# if (( ${#} )); then
#     echo "INFO: running ziti-edge-tunnel"
#     set -x
#     "./build/programs/ziti-edge-tunnel/${cmake_config}/ziti-edge-tunnel" ${@}
# fi