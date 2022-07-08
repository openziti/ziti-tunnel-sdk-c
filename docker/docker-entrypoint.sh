#!/usr/bin/env bash

#
# Copyright 2021 NetFoundry Inc.
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

set -e -u -o pipefail

function alldone() {
    # if successfully sent to background then send SIGINT to trigger a cleanup
    # of iptables mangle rules and loopback assignments
    [[ "${ZITI_EDGE_TUNNEL_PID:-}" =~ ^[0-9]+$ ]] && {
        kill -INT "$ZITI_EDGE_TUNNEL_PID"
        # let entrypoint script exit after ziti-tunnel PID
        wait "$ZITI_EDGE_TUNNEL_PID"
    }
}
trap alldone exit

IDENTITIES_DIR="/ziti-edge-tunnel"
if ! [[ -d "${IDENTITIES_DIR}" ]]; then
    echo "ERROR: need directory ${IDENTITIES_DIR} to find tokens and identities" >&2
    exit 1
fi

if ! mountpoint "${IDENTITIES_DIR}" &>/dev/null; then
    echo "WARN: the identities directory only available inside this container because ${IDENTITIES_DIR} is not a mounted volume. Be careful to not publish this image with identity inside or lose access to the identity by removing the image prematurely." >&2
fi

# IOTEDGE_DEVICEID is a standard var assigned by Azure IoT
if [[ -z "${NF_REG_NAME:-}" ]]; then
    if [[ -n "${IOTEDGE_DEVICEID:-}" ]]; then
        echo "INFO: setting NF_REG_NAME to \${IOTEDGE_DEVICEID} (${IOTEDGE_DEVICEID})"
        NF_REG_NAME="${IOTEDGE_DEVICEID}"
    fi
fi

typeset -a TUNNEL_OPTS
# if identity file, else multiple identities dir
if [[ -n "${NF_REG_NAME:-}" ]]; then
    IDENTITY_FILE="${IDENTITIES_DIR}/${NF_REG_NAME}.json"
    TUNNEL_OPTS=("--identity" "${IDENTITY_FILE}")
    : ${NF_REG_WAIT:=1}
    if [[ "${NF_REG_WAIT}" =~ ^[0-9]+$ ]]; then
        echo "DEBUG: waiting ${NF_REG_WAIT}s for ${IDENTITY_FILE} (or token) to appear"
    elif (( "${NF_REG_WAIT}" < 0 )); then
        echo "DEBUG: waiting forever for ${IDENTITY_FILE} (or token) to appear"
    else
        echo "ERROR: need integer for NF_REG_WAIT" >&2
        exit 1
    fi
    while (( $NF_REG_WAIT > 0 || $NF_REG_WAIT < 0)); do
        # if non-empty identity file
        if [[ -s "${IDENTITY_FILE}" ]]; then
            echo "INFO: found identity file ${IDENTITY_FILE}"
            break 1
        # look for enrollment token
        else
            echo "INFO: identity file ${IDENTITY_FILE} does not exist"
            for dir in "/var/run/secrets/netfoundry.io/enrollment-token" "${IDENTITIES_DIR}"; do
                JWT_CANDIDATE="${dir}/${NF_REG_NAME}.jwt"
                echo "INFO: looking for ${JWT_CANDIDATE}"
                if [[ -s "${JWT_CANDIDATE}" ]]; then
                    JWT_FILE="${JWT_CANDIDATE}"
                    break 1
                fi
            done
            if [[ -n "${JWT_FILE:-}" ]]; then
                echo "INFO: enrolling ${JWT_FILE}"
                ziti-edge-tunnel enroll --jwt "${JWT_FILE}" --identity "${IDENTITY_FILE}" || {
                    echo "ERROR: failed to enroll with token from ${JWT_FILE} ($(wc -c < "${JWT_FILE}")B)" >&2
                    exit 1
                }
            elif [[ -n "${NF_REG_TOKEN:-}" ]]; then
                echo "INFO: attempting enrollment with NF_REG_TOKEN"
                ziti-edge-tunnel enroll --jwt - --identity "${IDENTITY_FILE}" <<< "${NF_REG_TOKEN}" || {
                    echo "ERROR: failed to enroll with token from NF_REG_TOKEN ($(wc -c <<<"${NF_REG_TOKEN}")B)" >&2
                    exit 1
                }
            elif [[ -n "${NF_REG_STDIN:-}" ]]; then
                echo "INFO: trying to get token from stdin" >&2
                ziti-edge-tunnel enroll --jwt - --identity "${IDENTITY_FILE}" || {
                    echo "ERROR: failed to enroll with token from stdin" >&2
                    exit 1
                }
            fi
        fi
        # decrement the wait seconds until zero or forever if negative
        let NF_REG_WAIT--
        sleep 1
    done
else
    typeset -a JSON_FILES
    JSON_FILES=( $(ls -1 "${IDENTITIES_DIR}"/*.json) )
    if [[ ${#JSON_FILES[*]} -gt 0 ]]; then
        echo "INFO: NF_REG_NAME not set, loading ${#JSON_FILES[*]} identities from ${IDENTITIES_DIR}"
        TUNNEL_OPTS=("--identity-dir" "${IDENTITIES_DIR}")
    else
        echo "ERROR: NF_REG_NAME not set and zero identities found in ${IDENTITIES_DIR}" >&2
        exit 1
    fi
fi

echo "DEBUG: evaluating positionals: $*"
if (( ${#} )) && [[ ${1:0:3} == run ]]; then
    TUNNEL_RUN_MODE=${1}
    shift
else
    TUNNEL_RUN_MODE=run
fi

echo "INFO: running ziti-edge-tunnel"
set -x
ziti-edge-tunnel "${TUNNEL_RUN_MODE}" "${TUNNEL_OPTS[@]}" "${@}" &
ZITI_EDGE_TUNNEL_PID=$!
wait $ZITI_EDGE_TUNNEL_PID
