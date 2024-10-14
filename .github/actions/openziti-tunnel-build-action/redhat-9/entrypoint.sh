#!/usr/bin/env bash
#
# RedHat 9
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
    cmake_config="RelWithDebInfo"
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

(
  cd "${VCPKG_ROOT}"
  git checkout master
  git pull
  ./bootstrap-vcpkg.sh -disableMetrics
)

(
    [[ -d ./build ]] && rm -r ./build
    cmake -E make_directory ./build  
    # allow unset for scl_source scripts
    set +u
    cmake \
        --preset "${cmake_preset}" \
        -DCMAKE_BUILD_TYPE="${cmake_config}" \
        -DVCPKG_OVERLAY_PORTS=./.github/actions/openziti-tunnel-build-action/redhat-9/vcpkg-overlays \
        -DBUILD_DIST_PACKAGES=ON \
        "${TLSUV_TLSLIB:+-DTLSUV_TLSLIB=${TLSUV_TLSLIB}}" \
        -S . \
        -B ./build 
    cmake \
        --build ./build \
        --config "${cmake_config}" \
        --target package \
        --verbose
)
