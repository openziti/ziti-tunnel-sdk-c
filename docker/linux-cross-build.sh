#!/usr/bin/env bash
#
# cross-compile the Linux artifacts for the target architecture on amd64
# 

set -o pipefail -e -u
set -x

DIRNAME=$(dirname $0)
REPO_DIR=${DIRNAME}/..            # parent of the top-level dir where this script lives
: ${TARGET:="bundle"}
: ${BUILD_DIST_PACKAGES:="OFF"}
: ${DISABLE_LIBSYSTEMD_FEATURE:="OFF"}

if (( ${#} )); then
    for OPT in ${*}; do
        case $OPT in
            --package)
                TARGET="package"
                BUILD_DIST_PACKAGES="ON"
                shift
            ;;
            --no-systemd)
                DISABLE_LIBSYSTEMD_FEATURE="ON"
                shift
            ;;
        esac
    done
fi

# if no architectures supplied then default list of three
if (( ${#} )); then
    typeset -a JOBS=(${@})
else
    typeset -a JOBS=(amd64 arm64 arm)
fi

for ARCH in ${JOBS[@]}; do
    CMAKE_BUILD_DIR=${REPO_DIR}/build-${ARCH} # adjacent the top-level dir where this script lives
    [[ -d ${CMAKE_BUILD_DIR} ]] && rm -rf ${CMAKE_BUILD_DIR}
    mkdir ${CMAKE_BUILD_DIR}
#    cd ${CMAKE_BUILD_DIR}
    case ${ARCH} in
        amd64)  { cmake \
                    -DCMAKE_BUILD_TYPE=Release \
                    -DCMAKE_TOOLCHAIN_FILE=${REPO_DIR}/toolchains/default.cmake \
                    -DBUILD_DIST_PACKAGES=${BUILD_DIST_PACKAGES} \
                    -DDISABLE_LIBSYSTEMD_FEATURE=${DISABLE_LIBSYSTEMD_FEATURE} \
                    -S ${REPO_DIR} \
                    -B ${CMAKE_BUILD_DIR} \
                && cmake \
                    --build ${CMAKE_BUILD_DIR} \
                    --target ${TARGET} \
                    --verbose;
                }
        ;;
        arm64)  { cmake \
                    -DCMAKE_BUILD_TYPE=Release \
                    -DCMAKE_TOOLCHAIN_FILE=${REPO_DIR}/toolchains/Linux-arm64.cmake \
                    -DBUILD_DIST_PACKAGES=${BUILD_DIST_PACKAGES} \
                    -DDISABLE_LIBSYSTEMD_FEATURE=${DISABLE_LIBSYSTEMD_FEATURE} \
                    -S ${REPO_DIR} \
                    -B ${CMAKE_BUILD_DIR} \
                && cmake \
                    --build ${CMAKE_BUILD_DIR} \
                    --target ${TARGET} \
                    --verbose;
                }
        ;;
        arm)    { cmake \
                    -DCMAKE_BUILD_TYPE=Release \
                    -DCMAKE_TOOLCHAIN_FILE=${REPO_DIR}/toolchains/Linux-arm.cmake \
                    -DBUILD_DIST_PACKAGES=${BUILD_DIST_PACKAGES} \
                    -DDISABLE_LIBSYSTEMD_FEATURE=${DISABLE_LIBSYSTEMD_FEATURE} \
                    -S ${REPO_DIR} \
                    -B ${CMAKE_BUILD_DIR} \
                && cmake \
                    --build ${CMAKE_BUILD_DIR} \
                    --target ${TARGET} \
                    --verbose;
                }
        ;;
        *)      echo "ERROR: invalid architecture '${ARCH}', must be one of amd64, arm, arm64" >&2
                exit 1
        ;;
    esac
done
