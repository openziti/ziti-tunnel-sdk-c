#!/usr/bin/env bash
#
# build the Linux artifacts for amd64, arm64
#
# runs one background job per desired architecture unless there are too few CPUs
#
# 

set -o pipefail -e -u
set -x

DIRNAME=$(dirname $0)
REPO_DIR=${DIRNAME}/..            # parent of the top-level dir where this script lives
: ${USE_OPENSSL:="OFF"}
: ${TARGET:="bundle"}
: ${BUILD_DIST_PACKAGES:="OFF"}

if (( ${#} )) && [[ $1 == --openssl ]]; then
    shift
    USE_OPENSSL="ON"
fi

if (( ${#} )) && [[ $1 == --package ]]; then
    shift
    USE_OPENSSL="ON"
    TARGET="package"
    BUILD_DIST_PACKAGES="ON"

fi

# if no architectures supplied then default list of three
if (( ${#} )); then
    typeset -a JOBS=(${@})
else
    typeset -a JOBS=(amd64 arm64 arm)
fi

typeset -A BUILDS

for ARCH in ${JOBS[@]}; do
    CMAKE_BUILD_DIR=${REPO_DIR}/build-${ARCH} # adjacent the top-level dir where this script lives
    [[ -d ${CMAKE_BUILD_DIR} ]] && rm -rf ${CMAKE_BUILD_DIR}
    mkdir ${CMAKE_BUILD_DIR}
#    cd ${CMAKE_BUILD_DIR}
    case ${ARCH} in
        amd64)  { cmake \
                    -DCMAKE_BUILD_TYPE=Release \
                    -DCMAKE_TOOLCHAIN_FILE=${REPO_DIR}/toolchains/default.cmake \
                    -DUSE_OPENSSL=${USE_OPENSSL} \
                    -DBUILD_DIST_PACKAGES=${BUILD_DIST_PACKAGES} \
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
                    -DUSE_OPENSSL=${USE_OPENSSL} \
                    -DBUILD_DIST_PACKAGES=${BUILD_DIST_PACKAGES} \
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
                    -DUSE_OPENSSL=${USE_OPENSSL} \
                    -DBUILD_DIST_PACKAGES=${BUILD_DIST_PACKAGES} \
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
