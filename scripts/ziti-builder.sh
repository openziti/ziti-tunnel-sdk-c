#!/usr/bin/env bash
#
# build this project in the ziti-builder container
#

set -o errexit -o nounset -o pipefail
# set -o xtrace

BASENAME="$(basename "${0}")"
BASEDIR="$(cd "$(dirname "${0}")" && pwd)"  # full path to scripts dir
SCRIPTSDIR="$(basename "${BASEDIR}")"       # relative path to scripts dir, only works if executable is homed in a top-level dir of the project, .e.g. "/scripts"
REPODIR="$(dirname "${BASEDIR}")"           # path to project root is parent of scripts dir

[[ -x ${REPODIR}/${SCRIPTSDIR}/${BASENAME} ]] || {
    echo "ERROR: ${REPODIR}/${SCRIPTSDIR}/${BASENAME} is not executable" >&2
    exit 1
}

# set in ziti-builder image, but this default allows hacking the script to run
# outside the ziti-builder container
: "${GIT_CONFIG_GLOBAL:=/tmp/ziti-builder-gitconfig}"

[[ ${1:-} =~ -h|(--)?help ]] && {
    echo -e "\nUsage: ${BASENAME} [CMD] [ARGS...]"\
            "\n\nRuns CMD in the ziti-builder container, and builds the"\
            "\ndefault target if no CMD is specified\n"\
            "\n    -c  [Release|Debug]  set CMAKE_BUILD_TYPE (default: Release)"\
            "\n    -p  CMAKE_PRESET     set CMAKE_TOOLCHAIN_FILE preset (default: ci-linux-x64)"\
            "\n    -t  [bundle|package] set CMAKE_TARGET (default: ziti-edge-tunnel)"
    exit 0
}

function set_git_safe_dirs() {
    # workspace dir for each build env is added to "safe" dirs in global config
    # so both runner and builder containers trust these dirs owned by different
    # UIDs from that of Git's EUID. This is made necessary by newly-enforced
    # directory boundaries in Git v2.35.2 ref:
    # https://lore.kernel.org/git/xmqqv8veb5i6.fsf@gitster.g/
    local -a SAFE_DIRS=(
        "/github/workspace"
    )
    # the container environment defines GIT_CONFIG_GLOBAL=/tmp/ziti-builder-gitconfig
    for SAFE in "${SAFE_DIRS[@]}" "${@}"; do
        git config --file "$GIT_CONFIG_GLOBAL" --add safe.directory "${SAFE}"
    done
}

function set_workspace(){
    # let GitHub Actions override the workspace dir
    if [[ -n "${GITHUB_WORKSPACE:-}" ]]; then
        WORKDIR="${GITHUB_WORKSPACE}"
    else
        export WORKDIR="/github/workspace"
    fi

    # if project is mounted on WORKDIR then build, else restart in container
    if [[ -x "${WORKDIR}/${SCRIPTSDIR}/${BASENAME}" ]]; then
        # container environment defines BUILD_ENVIRONMENT=ziti-builder-docker
        if [[ "${BUILD_ENVIRONMENT:-}" == "ziti-builder-docker" ]]; then
            echo "INFO: running in ziti-builder container"
            set_git_safe_dirs "${WORKDIR}"
        else
            echo "ERROR: not running in ziti-builder container" >&2
            exit 1
        fi
    else
        echo -e "INFO: project not mounted on ${WORKDIR}"\
                "\nINFO: re-running in ziti-builder container"
        set -x
        eval exec docker run \
            --rm \
            --user "${UID}" \
            --volume "${REPODIR}:${WORKDIR}" \
            "${ZITI_SDK_DIR:+--volume=${ZITI_SDK_DIR}:${ZITI_SDK_DIR}}" \
            --platform "linux/amd64" \
            --env "VCPKG_DEFAULT_BINARY_CACHE=${WORKDIR}/.cache" \
            --env "TLSUV_TLSLIB" \
            --env "ZITI_SDK_DIR" \
            "openziti/ziti-builder:${ZITI_BUILDER_TAG:-latest}" \
                "${WORKDIR}/${SCRIPTSDIR}/${BASENAME}" "${@}"
    fi
}

function main() {
    echo "INFO: GIT_DISCOVERY_ACROSS_FILESYSTEM=${GIT_DISCOVERY_ACROSS_FILESYSTEM:-}"
    echo "INFO: WORKDIR=${PWD}"
    echo "INFO: $(git --version)"
    echo "INFO: GIT_CONFIG_GLOBAL=${GIT_CONFIG_GLOBAL:-}"
    # use this value to detect whether any options were passed so we can warn if
    # they're being ignored when an override command is sent at the same time
    : "${OPTS:=0}"

    while getopts 'c:e:p:t:' OPT; do
        case "${OPT}" in
            c)  CMAKE_CONFIG="${OPTARG}"
                OPTS=1
            ;;
            e)  CMAKE_EXTRA_ARGS="${OPTARG}"
            ;;
            p)  CMAKE_PRESET="${OPTARG}"
                OPTS=1
            ;;
            t)  CMAKE_TARGET="${OPTARG}"
                OPTS=1
                if [[ ${CMAKE_TARGET} == package ]]; then
                    BUILD_DIST_PACKAGES=ON
                fi
            ;;
            *)  echo "ERROR: invalid option: ${OPT}" >&2
                return 1
            ;;
        esac
    done
    shift $((OPTIND-1))
    # if args then run them, else clean build output dir and build default target
    if (( $# )); then
        if (( OPTS )); then
            echo "WARN: ignoring options because override command is present" >&2
        fi
        cd "${REPODIR}"
        exec "${@}"
    else
        [[ -d ./build ]] && rm -rf ./build
        [[ -d ./.cache ]] || mkdir -v ./.cache
        cmake \
            -E make_directory \
            ./build  
        cmake \
            --preset "${CMAKE_PRESET:-ci-linux-x64}" \
            -DCMAKE_BUILD_TYPE="${CMAKE_CONFIG:-Release}" \
            -DBUILD_DIST_PACKAGES="${BUILD_DIST_PACKAGES:-OFF}" \
            "${TLSUV_TLSLIB:+-DTLSUV_TLSLIB=${TLSUV_TLSLIB}}" \
            "${ZITI_SDK_DIR:+-DZITI_SDK_DIR=${ZITI_SDK_DIR}}" \
            -S . \
            -B ./build \
            "${CMAKE_EXTRA_ARGS:-}"
        cmake \
            --build ./build \
            --config "${CMAKE_CONFIG:-Release}" \
            --target "${CMAKE_TARGET:-ziti-edge-tunnel}" \
            --verbose
    fi
    ls -lAh ./build/programs/ziti-edge-tunnel/Release/ziti-edge-tunnel
}

# set global WORKDIR
set_workspace "${@}"

# run main() in WORKDIR
cd "${WORKDIR}"
main "${@}"