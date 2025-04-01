#!/usr/bin/env bash

#
# Copyright NetFoundry Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

set -o errexit -o nounset -o pipefail

function alldone() {
    # if successfully sent to background then send SIGTERM because ZET does not respond to SIGINT
    [[ "${ZITI_EDGE_TUNNEL_PID:-}" =~ ^[0-9]+$ ]] && {
        kill -0 "$ZITI_EDGE_TUNNEL_PID" &>/dev/null && {
            kill -TERM "$ZITI_EDGE_TUNNEL_PID"
            # let entrypoint script exit after ziti-edge-tunnel PID
            wait "$ZITI_EDGE_TUNNEL_PID"
        }
    }
}
trap alldone SIGTERM SIGINT EXIT

unset \
    IDENTITY_FILE \
    JSON_FILES \
    JWT_CANDIDATE \
    JWT_FILE \
    TUNNEL_OPTS \
    TUNNEL_RUN_MODE

# adapt deprecated NF_REG_* env vars to undefined ZITI_* env vars
if [[ -z "${ZITI_IDENTITY_BASENAME:-}" ]]; then
    if [[ -n "${NF_REG_NAME:-}" ]]; then
        echo "WARN: replacing deprecated NF_REG_NAME with ZITI_IDENTITY_BASENAME=${NF_REG_NAME}"
        ZITI_IDENTITY_BASENAME="${NF_REG_NAME}"
    elif [[ -n "${IOTEDGE_DEVICEID:-}" ]]; then
        echo "WARN: replacing deprecated IOTEDGE_DEVICEID with ZITI_IDENTITY_BASENAME=${IOTEDGE_DEVICEID}"
        ZITI_IDENTITY_BASENAME="${IOTEDGE_DEVICEID}"
    fi
fi
if [[ -z "${ZITI_ENROLL_TOKEN:-}" && -n "${NF_REG_TOKEN:-}" ]]; then
    echo "WARN: replacing deprecated NF_REG_TOKEN with ZITI_ENROLL_TOKEN=${NF_REG_TOKEN}"
    ZITI_ENROLL_TOKEN="${NF_REG_TOKEN}"
fi
if [[ -z "${ZITI_IDENTITY_WAIT:-}" && -n "${NF_REG_WAIT:-}" ]]; then
    echo "WARN: replacing deprecated var NF_REG_WAIT with ZITI_IDENTITY_WAIT=${NF_REG_WAIT}"
    ZITI_IDENTITY_WAIT="${NF_REG_WAIT}"
fi

# assign default identity dir if not set in parent env; this is a writeable path within the container image
: "${ZITI_IDENTITY_DIR:="/ziti-edge-tunnel"}"

# if enrolled identity JSON is provided then write it to a file in the identities dir
if [[ -n "${ZITI_IDENTITY_JSON:-}" ]]; then
    if [[ -z "${ZITI_IDENTITY_BASENAME:-}" ]]; then
        ZITI_IDENTITY_BASENAME="ziti_id"
    fi
    IDENTITY_FILE="${ZITI_IDENTITY_DIR}/${ZITI_IDENTITY_BASENAME}.json"
    if [[ -s "${IDENTITY_FILE}" ]]; then
        echo "WARN: clobbering non-empty Ziti identity file ${IDENTITY_FILE} with contents of env var ZITI_IDENTITY_JSON" >&2
    fi
    echo "${ZITI_IDENTITY_JSON}" > "${IDENTITY_FILE}"
# if an enrollment token is provided then write it to a file in the identities dir so it will be found in the next step
# and used to enroll
elif [[ -n "${ZITI_ENROLL_TOKEN:-}" ]]; then
    if [[ -z "${ZITI_IDENTITY_BASENAME:-}" ]]; then
        ZITI_IDENTITY_BASENAME="ziti_id"
    fi
    JWT_FILE="${ZITI_IDENTITY_DIR}/${ZITI_IDENTITY_BASENAME}.jwt"
    if [[ -s "${JWT_FILE}" ]]; then
        echo "WARN: clobbering non-empty Ziti enrollment token file ${JWT_FILE} with contents of env var ZITI_ENROLL_TOKEN" >&2
    fi
    echo "${ZITI_ENROLL_TOKEN}" > "${JWT_FILE}"
# otherwise, assume the identities dir is a mounted volume with identity files or tokens
else
    if ! [[ -d "${ZITI_IDENTITY_DIR}" ]]; then
        echo "ERROR: need directory ${ZITI_IDENTITY_DIR} to find tokens and identities" >&2
        exit 1
    fi
fi

typeset -a TUNNEL_OPTS
# if identity basename is specified then look for an identity file with that name, else load all identities in the
# identities dir mountpoint
if [[ -n "${ZITI_IDENTITY_BASENAME:-}" ]]; then
    IDENTITY_FILE="${ZITI_IDENTITY_DIR}/${ZITI_IDENTITY_BASENAME}.json"
    TUNNEL_OPTS=("--identity" "${IDENTITY_FILE}")

    # if wait is specified then wait for the identity file or token to appear
    : "${ZITI_IDENTITY_WAIT:=3}"
    # if a positive integer then wait that many seconds for the identity file or token to appear
    if [[ "${ZITI_IDENTITY_WAIT}" =~ ^[0-9]+$ ]]; then
        echo "DEBUG: waiting ${ZITI_IDENTITY_WAIT}s for ${IDENTITY_FILE} (or token) to appear"
    # if a negative integer then wait forever for the identity file or token to appear
    elif (( ZITI_IDENTITY_WAIT < 0 )); then
        echo "DEBUG: waiting forever for ${IDENTITY_FILE} (or token) to appear"
    # error if not an integer
    else
        echo "ERROR: ZITI_IDENTITY_WAIT must be an integer (seconds to wait)" >&2
        exit 1
    fi
    while (( ZITI_IDENTITY_WAIT > 0 || ZITI_IDENTITY_WAIT < 0)); do
        # if non-empty identity file
        if [[ -s "${IDENTITY_FILE}" ]]; then
            echo "INFO: found identity file ${IDENTITY_FILE}"
            break 1
        # look for enrollment token
        else
            echo "DEBUG: identity file ${IDENTITY_FILE} not found"
            for dir in  "/var/run/secrets/netfoundry.io/enrollment-token" \
                        "/enrollment-token" \
                        "${ZITI_IDENTITY_DIR}"; do
                JWT_CANDIDATE="${dir}/${ZITI_IDENTITY_BASENAME}.jwt"
                if [[ -s "${JWT_CANDIDATE}" ]]; then
                    JWT_FILE="${JWT_CANDIDATE}"
                    break 1
                else
                    echo "DEBUG: ${JWT_CANDIDATE} not found"
                fi
            done
            if [[ -n "${JWT_FILE:-}" ]]; then
                echo "INFO: enrolling ${JWT_FILE}"
                ziti-edge-tunnel enroll --jwt "${JWT_FILE}" --identity "${IDENTITY_FILE}" || {
                    echo "ERROR: failed to enroll with token from ${JWT_FILE} ($(wc -c < "${JWT_FILE}")B)" >&2
                    exit 1
                }
            elif [[ -n "${ZITI_ENROLL_TOKEN:-}" ]]; then
                echo "INFO: attempting enrollment with ZITI_ENROLL_TOKEN"
                ziti-edge-tunnel enroll --jwt - --identity "${IDENTITY_FILE}" <<< "${ZITI_ENROLL_TOKEN}" || {
                    echo "ERROR: failed to enroll with token from ZITI_ENROLL_TOKEN ($(wc -c <<<"${ZITI_ENROLL_TOKEN}")B)" >&2
                    exit 1
                }
            # this works but the legacy var name was never deprecated because of doubts about the utility of this
            # feature
            elif [[ -n "${NF_REG_STDIN:-}" ]]; then
                echo "INFO: trying to get token from stdin" >&2
                ziti-edge-tunnel enroll --jwt - --identity "${IDENTITY_FILE}" || {
                    echo "ERROR: failed to enroll with token from stdin" >&2
                    exit 1
                }
            fi
        fi
        # decrement the wait seconds until zero or forever if negative
        (( ZITI_IDENTITY_WAIT-- ))
        sleep 1
    done
# if no identity basename is specified then load all *.json files in the identities dir mountpoint, ignoring enrollment
# tokens
else
    typeset -a JSON_FILES
    mapfile -t JSON_FILES < <(ls -1 "${ZITI_IDENTITY_DIR}"/*.json)
    if [[ ${#JSON_FILES[*]} -gt 0 ]]; then
        echo "INFO: loading ${#JSON_FILES[*]} identities from ${ZITI_IDENTITY_DIR}"
        TUNNEL_OPTS=("--identity-dir" "${ZITI_IDENTITY_DIR}")
    else
        echo "ERROR: ZITI_IDENTITY_BASENAME not set and zero identities found in ${ZITI_IDENTITY_DIR}" >&2
        exit 1
    fi
fi

echo "DEBUG: checking for run mode as first positional in: $*"
if (( ${#} )) && [[ ${1:0:3} == run ]]; then
    TUNNEL_RUN_MODE=${1}
    shift
else
    TUNNEL_RUN_MODE=run
fi

echo "INFO: running: ziti-edge-tunnel ${TUNNEL_RUN_MODE} ${TUNNEL_OPTS[*]} ${*}"
ziti-edge-tunnel "${TUNNEL_RUN_MODE}" "${TUNNEL_OPTS[@]}" "${@}" &
ZITI_EDGE_TUNNEL_PID=$!
echo "DEBUG: waiting for ziti-edge-tunnel PID: ${ZITI_EDGE_TUNNEL_PID}"
wait $ZITI_EDGE_TUNNEL_PID
