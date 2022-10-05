# Ziti-edge-tunnel Docker Image

The container image `openziti/ziti-edge-tunnel` is published in Docker Hub and frequently updated with new releases. You may subscribe to `:latest` (default) or pin a version for stability e.g. `:0.19.11`.

This image runs `ziti-edge-tunnel`, the OpenZiti tunneler for Linux. `ziti-edge-tunnel run` captures
network traffic that is destined for Ziti services and proxies the packet payloads
to the associated Ziti service. The `ziti-edge-tunnel run-host` hosting-only mode is useful as a sidecar for publishing containerized servers located in a Docker bridge network or any other server running in the Docker host's network.

See the [the Linux tunneler doc](https://openziti.github.io/ziti/clients/linux.html) for general info not pertinent to running with Docker.

This container image requires access to a Ziti enrollment token (JWT), and typically uses a persistent
volume mounted at `/ziti-edge-tunnel` to save the configuration file that is created
when the one-time enrollment token is consumed.

## Variables

- `NF_REG_NAME`: Required: This is the basename of the enrollment (.jwt) and identity (.json) files the tunneler will use
- `NF_REG_TOKEN`: Optional if `${NF_REG_NAME}.jwt` is provided: This is the JWT as a string
- `NF_REG_WAIT`: Optional: max seconds to wait for the JWT or JSON file to appear

## Volumes

- `/ziti-edge-tunnel`: The permanent identity configuration JSON file that results from enrollment will be stored
  here. This volume should be persistent.

## Files

The directory containing the enrollment token (JWT) file is typically mounted as a volume.
The token must be in a file named `${NF_REG_NAME}.jwt`. After the first run there will be an additional file name `${NF_REG_NAME}.json`, the permanent identity configuration JSON file. This file contains the private key and user certificate.

## Examples

Mode `run-host` is useful for publishing a server to the OpenZiti Network. This example uses the Docker host's network, but you could instead run the container in a Docker bridge for the purpose of publishing a bridge-isolated server that is known by its Docker-internal domain name.

```bash
# current directory contains enrollment token file ziti_id.jwt
docker run \
    --name ziti-host \
    --network host \
    --volume ${PWD}:/ziti-edge-tunnel \
    --env NF_REG_NAME=ziti_id \
    openziti/ziti-edge-tunnel \
    run-host
```

Transparent Proxy `run` mode configures an OpenZiti nameserver running on the local device and captures any layer 4 traffic that matches an authorized service destination.

```bash
# current directory contains enrollment token file ziti_id.jwt
docker run \
    --name ziti-tun \
    --network host \
    --privileged \
    --volume ${PWD}:/ziti-edge-tunnel/ \
    --volume "/var/run/dbus/system_bus_socket:/var/run/dbus/system_bus_socket" \
    --device "/dev/net/tun:/dev/net/tun" \
    --env NF_REG_NAME=ziti_id \
    openziti/ziti-edge-tunnel
```

This example uses the included Docker Compose project to illustrate publishing a server container to your OpenZiti Network.

1. Create an OpenZiti Config with type `intercept.v1`.

    ```json
    {
        "addresses": [
            "hello-docker.ziti"
        ],
        "protocols": [
            "tcp"
        ],
        "portRanges": [
            {
            "low": 80,
            "high": 80
            }
        ]
    }
    ```

1. Create an OpenZiti Config with type `host.v1`

    ```json
    {
        "port": 80,
        "address": "hello",
        "protocol": "tcp"
    }
    ```

1. Create a service associating the two configs with a role attribute like "#HelloServices"
1. Create an identity for your client tunneler named like "MyClient" and load the identity
1. Create an identity named like "DockerHost" and download the enrollment token in the same directory as `docker-compose.yml` i.e. "DockerHost.jwt"
1. Create a Bind service policy assigning "#HelloServices" to be bound by "@DockerHost"
1. Create a Dial service policy granting access to "#HelloServices" to your client tunneler's identity "@MyClient"
1. Run the demo server

    ```bash
    docker-compose up --detach hello
    ```

1. Run the tunneler

    ```bash
    NF_REG_NAME=DockerHost docker-compose up --detach ziti-host
    ```

1. Access the demo server via your OpenZiti Network: http://hello-docker.ziti

Please reference [the included Compose project](docker-compose.yml) for examples that exercise the various options and run modes.
