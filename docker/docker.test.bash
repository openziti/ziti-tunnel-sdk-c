#!/usr/bin/env bash

# exec this script with BASH v4+ on Linux to test the checked-out ziti-tunnel-sdk-c repo's Docker deployments

set -o errexit
set -o nounset
set -o pipefail
set -o xtrace

cleanup(){
    if ! (( I_AM_ROBOT ))
    then
        echo "WARNING: destroying all controller and router state volumes in 30s; set I_AM_ROBOT=1 to suppress this message" >&2
        sleep 30
    fi
	docker compose down --volumes --remove-orphans
    echo "DEBUG: cleanup complete"
}

debug(){

    set -o errexit
    docker compose logs
    docker compose exec -T quickstart bash << BASH

set -o errexit
set -o nounset
set -o pipefail
set -o xtrace

ziti edge list edge-routers
ziti edge list terminators
ziti edge policy-advisor services httpbin-service --quiet

BASH

    for SVC in ziti-{host,tun}
    do
        docker compose exec -T "${SVC}" bash << BASH || true

set -o errexit
set -o nounset
set -o pipefail
set -o xtrace

ziti-edge-tunnel tunnel_status | jq

BASH
    done

}

checkCommand() {
    if ! command -v "$1" &>/dev/null; then
        logError "this script requires command '$1'."
        $1
    fi
}

portcheck(){
    PORT="${1}"
    if nc -zv localhost "$PORT" &>/dev/null
    then
		echo "ERROR: port $PORT is already allocated" >&2
        return 1
    else
		echo "DEBUG: port $PORT is available"
        return 0
    fi
}

BASEDIR="$(cd "$(dirname "${0}")" && pwd)"
REPOROOT="$(cd "${BASEDIR}/.." && pwd)"
cd "${REPOROOT}"

declare -a BINS=(grep docker ./scripts/ziti-builder.sh curl nc jq)
for BIN in "${BINS[@]}"; do
    checkCommand "$BIN"
done

: "${I_AM_ROBOT:=0}"
: "${ZITI_CTRL_ADVERTISED_PORT:=12802}"
: "${ZITI_ROUTER_PORT:=30224}"
# : "${ZIGGY_UID:=$(id -u)}"

if [[ -n "${ZITI_EDGE_TUNNEL_BIN:-}" && -s "${ZITI_EDGE_TUNNEL_BIN}" ]]; then
    if ! [[ "$(realpath "${ZITI_EDGE_TUNNEL_BIN}")" == "$(realpath "./build/amd64/linux/ziti-edge-tunnel")" ]]; then
        mkdir -p ./build/amd64/linux
        cp "${ZITI_EDGE_TUNNEL_BIN}" ./build/amd64/linux/ziti-edge-tunnel
    fi
else
    bash -x ./scripts/ziti-builder.sh -p ci-linux-x64
    mkdir -p ./build/amd64/linux
    cp ./build/programs/ziti-edge-tunnel/Release/ziti-edge-tunnel ./build/amd64/linux/ziti-edge-tunnel
fi

ZITI_EDGE_TUNNEL_IMAGE="ziti-edge-tunnel"
ZITI_EDGE_TUNNEL_TAG="local"

docker build \
--build-arg "DOCKER_BUILD_DIR=./docker" \
--tag "${ZITI_EDGE_TUNNEL_IMAGE}:${ZITI_EDGE_TUNNEL_TAG}" \
--file "./docker/ziti-edge-tunnel.Dockerfile" \
"${PWD}"

ZITI_HOST_IMAGE="ziti-host"
ZITI_HOST_TAG="local"

docker build \
--build-arg "ZITI_EDGE_TUNNEL_IMAGE=${ZITI_EDGE_TUNNEL_IMAGE}" \
--build-arg "ZITI_EDGE_TUNNEL_TAG=${ZITI_EDGE_TUNNEL_TAG}" \
--tag "${ZITI_HOST_IMAGE}:${ZITI_HOST_TAG}" \
--file "./docker/ziti-host.Dockerfile" \
"${PWD}"

# also let docker inherit the vars that define the tunneler images
export \
ZITI_EDGE_TUNNEL_IMAGE \
ZITI_EDGE_TUNNEL_TAG \
ZITI_HOST_IMAGE \
ZITI_HOST_TAG

export COMPOSE_FILE="docker/compose.intercept.yml:docker/compose.host.yml:docker/compose.test.yml"

cleanup

# freshen ziti-controller, httpbin, etc. images
docker compose pull

for PORT in "${ZITI_CTRL_ADVERTISED_PORT}" "${ZITI_ROUTER_PORT}"
do
    portcheck "${PORT}"
done

# configure the quickstart container
export \
ZITI_CTRL_ADVERTISED_ADDRESS="ziti.127.0.0.1.sslip.io" \
ZITI_PWD="ziggypw" \
ZITI_CTRL_ADVERTISED_PORT \
ZITI_ROUTER_PORT

# run the check container that waits for a responsive controller agent
docker compose up quickstart-check

# run the script from heredoc inside the quickstart container after variable interpolation
docker compose exec -T quickstart bash << BASH

set -o errexit
set -o nounset
set -o pipefail
set -o xtrace

ziti edge login \
${ZITI_CTRL_ADVERTISED_ADDRESS}:${ZITI_CTRL_ADVERTISED_PORT} \
--ca=/home/ziggy/quickstart/pki/root-ca/certs/root-ca.cert \
--username=admin \
--password=${ZITI_PWD} \
--timeout=1 \
--verbose

ziti edge create identity "httpbin-client" \
    --jwt-output-file /tmp/httpbin-client.ott.jwt \
    --role-attributes httpbin-clients

ziti edge create identity "httpbin-host" \
    --jwt-output-file /tmp/httpbin-host.ott.jwt \
    --role-attributes httpbin-hosts

ziti edge create config "httpbin-intercept-config" intercept.v1 \
    '{"protocols":["tcp"],"addresses":["httpbin.ziti.internal"], "portRanges":[{"low":80, "high":80}]}'

ziti edge create config "httpbin-host-config" host.v1 \
    '{"protocol":"tcp", "address":"httpbin","port":8080}'

ziti edge create service "httpbin-service" \
    --configs httpbin-intercept-config,httpbin-host-config \
    --role-attributes test-services

ziti edge create service-policy "httpbin-bind-policy" Bind \
    --service-roles '#test-services' \
    --identity-roles '#httpbin-hosts'

ziti edge create service-policy "httpbin-dial-policy" Dial \
    --service-roles '#test-services' \
    --identity-roles '#httpbin-clients'
BASH

ZITI_ENROLL_TOKEN="$(docker compose exec quickstart cat /tmp/httpbin-host.ott.jwt)" \
docker compose up ziti-host --detach

ZITI_ENROLL_TOKEN="$(docker compose exec quickstart cat /tmp/httpbin-client.ott.jwt)" \
docker  compose up ziti-tun --detach

ATTEMPTS=3
DELAY=1

curl_cmd="curl --fail --connect-timeout 1 --silent --show-error --request POST --header 'Content-Type: application/json' --data '{\"ziti\": \"works\"}' http://httpbin.ziti.internal/post"
until ! (( --ATTEMPTS )) || eval "${curl_cmd}" &> /dev/null
do
    : $ATTEMPTS remaining attempts - waiting for httpbin service
    docker compose ps
    sleep ${DELAY}
done

if eval "${curl_cmd}" | jq .json
then
    (( I_AM_ROBOT )) || read -rp "Press [Enter] to continue..."
    cleanup
    : PASSED
    exit 0
else
    debug
    cleanup
    : FAILED
    exit 1
fi
