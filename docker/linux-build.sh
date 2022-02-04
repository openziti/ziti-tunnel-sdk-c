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

# if no architectures supplied then default list of three
if (( ${#} )); then
    typeset -a JOBS=(${@})
else
    typeset -a JOBS=(amd64 arm64)
fi

PROC_COUNT=$(nproc --all)
# compute the number of processors available for each job, rounded down to integer
PROCS_PER_JOB=$((PROC_COUNT / ${#JOBS[@]}))
# if multiple jobs and at least one processor for each job then background, else foreground with all available CPUs-1 (gox default)
if (( ${#JOBS[@]} > 1 && ${PROCS_PER_JOB} )); then 
    BACKGROUND="&"
    # initialize an associative array in which to map background PIDs to the ARCH being built
    typeset -A BUILDS
else
    BACKGROUND=""               # run normally in foreground
    PROCS_PER_JOB=${PROC_COUNT} # use all available CPUs
fi

for ARCH in ${JOBS[@]}; do
    CMAKE_BUILD_DIR=${REPO_DIR}/build-${ARCH} # adjacent the top-level dir where this script lives
    [[ -d ${CMAKE_BUILD_DIR} ]] && rm -rf ${CMAKE_BUILD_DIR}
    mkdir ${CMAKE_BUILD_DIR}
#    cd ${CMAKE_BUILD_DIR}
    case ${ARCH} in
        amd64)  { eval cmake \
                    -DCMAKE_TOOLCHAIN_FILE=${REPO_DIR}/toolchains/default.cmake \
                    -S ${REPO_DIR} \
                    -B ${CMAKE_BUILD_DIR} \
                && eval cmake \
                    --build ${CMAKE_BUILD_DIR} \
                    --target bundle \
                    --parallel ${PROCS_PER_JOB} \
                    --verbose;
                } ${BACKGROUND}
                (( ${PROCS_PER_JOB} )) && BUILDS[${!}]=${ARCH}  # if greater than zero procs per job then map background pid->arch
        ;;
        arm64)  { eval cmake \
                    -DCMAKE_BUILD_TYPE=Release \
                    -DCMAKE_TOOLCHAIN_FILE=${REPO_DIR}/toolchains/Linux-arm64.cmake \
                    -S ${REPO_DIR} \
                    -B ${CMAKE_BUILD_DIR} \
                && eval cmake \
                    --build ${CMAKE_BUILD_DIR} \
                    --target bundle \
                    --parallel ${PROCS_PER_JOB} \
                    --verbose;
                } ${BACKGROUND}
                (( ${PROCS_PER_JOB} )) && BUILDS[${!}]=${ARCH}
        ;;
        *)      echo "ERROR: invalid architecture '${ARCH}', must be one of amd64, arm, arm64" >&2
                exit 1
        ;;
    esac
done

# if not background in parallel then exit now with well earned success
[[ -z "${BACKGROUND:-}" ]] || exit 0

# Wait for builds in the background and exit with an error if any fail
EXIT=0
while true; do
    # "wait -p" requires BASH >=5.1 which is present in Ubuntu 20.10 and Debian Bullseye
    wait -n -p JOB_PID; JOB_RESULT=$?
    echo "Building for ${BUILDS[$JOB_PID]} finished with result ${JOB_RESULT}"
    (( ${JOB_RESULT} )) && EXIT=1
done

exit ${EXIT}
