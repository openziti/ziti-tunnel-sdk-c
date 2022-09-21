# Ziti-edge-tunnel Docker Image

Run `ziti-edge-tunnel`, the C-SDK tunneler for Linux. `ziti-edge-tunnel` captures
network traffic that is destined for Ziti services and proxies the packet payloads
to the associated Ziti service. See the [repo README](../README.md) and [the doc](https://openziti.github.io/ziti/clients/linux.html) for more details.

This container image requires access to a Ziti enrollment token (JWT), and a persistent
volume mounted at "/ziti-edge-tunnel" to save the configuration file that is created
when the one-time enrollment token is consumed.

## Variables

- `NF_REG_NAME`: Required: This is the basename of the identity config JSON file that ziti-edge-tunnel will use.
- `NF_REG_TOKEN`: Optional if `${NF_REG_NAME}.jwt` is provided: This is the JWT as a string
- `NF_REG_WAIT`: Optional: max seconds to wait for the JWT or JSON file to appear

## Volumes

- `/ziti-edge-tunnel`: The permanent identity configuration JSON file that results from enrollment will be stored
  here. This volume should be persistent.

## Files

The enrollment token (JWT) is typically mounted into the ziti-edge-tunnel container as a volume.
The token must be in a file named `${NF_REG_NAME}.jwt` that must be in one of the
following directories:

- `/ziti-edge-tunnel`: This would be used when running in the Docker engine (or IoT Edge).
   This could be a bind mount or a docker volume.

## Examples

Transparent Proxy `run` mode

```bash
mkdir ./ziti_id
cp ~/Downloads/ziti_id.jwt ./ziti_id
docker pull openziti/ziti-edge-tunnel
docker run \
    --name ziti-tproxy \
    --network host \
    --privileged \
    --volume ${PWD}:/ziti-edge-tunnel \
    --volume "/var/run/dbus/system_bus_socket:/var/run/dbus/system_bus_socket" \
    --device "/dev/net/tun:/dev/net/tun" \
    --env NF_REG_NAME=ziti_id \
    openziti/ziti-edge-tunnel
```

Service Bind `run-host` mode is useful for publishing a server to the OpenZiti Network

```bash
docker run \
    --name ziti-host \
    --network host \
    --volume ${PWD}:/ziti-edge-tunnel \
    --env NF_REG_NAME=ziti_id \
    openziti/ziti-edge-tunnel \
    run-host
```

Please reference [the included Compose project](docker-compose.yml) for more examples.