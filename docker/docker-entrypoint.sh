#!/usr/bin/env bash

set -e -u -o pipefail

function alldone() {
    # send SIGINT to ziti-edge-tunnel to trigger graceful exit
    kill -INT $ZITI_EDGE_TUNNEL_PID
    # let entrypoint script exit after ziti-edge-tunnel PID
    wait $ZITI_EDGE_TUNNEL_PID
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
if [ -z "${NF_REG_NAME}" ]; then
    if [ -n "${IOTEDGE_DEVICEID}" ]; then
        echo "INFO: setting NF_REG_NAME to \${IOTEDGE_DEVICEID} (${IOTEDGE_DEVICEID})"
        NF_REG_NAME="${IOTEDGE_DEVICEID}"
    fi
fi
if [ -z "${NF_REG_NAME}" ]; then
    echo "ERROR: please set the NF_REG_NAME environment variable when running this image" >&2
    exit 1
fi

json="${persisted_dir}/${NF_REG_NAME}.json"
if [ ! -f "${json}" ]; then
    echo "INFO: identity configuration ${json} does not exist"
    for dir in "/var/run/secrets/netfoundry.io/enrollment-token" "${persisted_dir}"; do
        _jwt="${dir}/${NF_REG_NAME}.jwt"
        echo "INFO: looking for ${_jwt}"
        if [ -f "${_jwt}" ]; then
            jwt="${_jwt}"
            break
        fi
    done
    if [ -z "${jwt}" ]; then
        echo "ERROR: ${NF_REG_NAME}.jwt was not found in the expected locations" >&2
        exit 1
    fi
    echo "INFO: enrolling ${jwt}"
    ziti-edge-tunnel enroll --jwt "${jwt}" --identity "${json}"
fi

echo "INFO: running ziti-edge-tunnel"
set -x
ziti-edge-tunnel run --identity "${json}" "${@}" &
ZITI_EDGE_TUNNEL_PID=$!
wait $ZITI_EDGE_TUNNEL_PID
