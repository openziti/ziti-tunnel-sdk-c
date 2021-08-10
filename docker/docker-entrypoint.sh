#!/usr/bin/env bash

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

# Ensure that ziti-edge-tunnel's identity is stored on a volume
# so we don't throw away the one-time enrollment token

persisted_dir="/ziti-edge-tunnel"
if ! mountpoint "${persisted_dir}"; then
    echo "ERROR: please run this image with a volume mounted on ${persisted_dir}" >&2
    exit 1
fi

# try to figure out the client name if it wasn't provided
if [[ -z "${NF_REG_NAME}" ]]; then
    if [[ -n "${IOTEDGE_DEVICEID}" ]]; then
        echo "INFO: setting NF_REG_NAME to \${IOTEDGE_DEVICEID} (${IOTEDGE_DEVICEID})"
        NF_REG_NAME="${IOTEDGE_DEVICEID}"
    fi
fi
if [[ -z "${NF_REG_NAME}" ]]; then
    echo "ERROR: please set the NF_REG_NAME environment variable when running this image" >&2
    exit 1
fi

# if not non-empty identity file then look for enrollment token
json="${persisted_dir}/${NF_REG_NAME}.json"
if [[ ! -s "${json}" ]]; then
    echo "INFO: identity configuration ${json} does not exist"
    for dir in "/var/run/secrets/netfoundry.io/enrollment-token" "${persisted_dir}"; do
        _jwt="${dir}/${NF_REG_NAME}.jwt"
        echo "INFO: looking for ${_jwt}"
        if [[ -s "${_jwt}" ]]; then
            jwt="${_jwt}"
            break
        fi
    done
    if [[ -n "${jwt:-}" ]]; then
        echo "INFO: enrolling ${jwt}"
        ziti-edge-tunnel enroll --jwt "${jwt}" --identity "${json}"
    elif [[ -n "${NF_REG_TOKEN:-}" ]]; then
        echo "INFO: attempting enrollment with NF_REG_TOKEN"
        ziti-edge-tunnel enroll --jwt - --identity "${json}" <<< "${NF_REG_TOKEN}" || {
            echo "ERROR: failed to enroll with token from NF_REG_TOKEN" >&2
            exit 1
        }
    else
        echo "INFO: ${NF_REG_NAME}.jwt was not found, trying stdin" >&2
        ziti-edge-tunnel enroll --jwt - --identity "${json}" || {
            echo "ERROR: failed to enroll with token from stdin" >&2
            exit 1
        }
    fi
fi

echo "INFO: running ziti-edge-tunnel"
set -x
ziti-edge-tunnel run --identity "${json}" "${@}" &
ZITI_EDGE_TUNNEL_PID=$!
wait $ZITI_EDGE_TUNNEL_PID
