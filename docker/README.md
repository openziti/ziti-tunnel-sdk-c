# Ziti-edge-tunnel Docker Image

Run `ziti-edge-tunnel`, the C-SDK tunneler for Linux. `ziti-edge-tunnel` captures
network traffic that is destined for Ziti services and proxies the packet payloads
to the associated Ziti service. See the [README](README.md) for more details.

This image requires access to a Ziti enrollment token (JWT), and a persistent
volume mounted at "/ziti-edge-tunnel" to save the configuration file that is created
when the one-time enrollment token is consumed.

## Variables

- `NF_REG_NAME`: The name of the identity that ziti-tunnel will assume.

## Volumes

- `/ziti-edge-tunnel`: Configuration files that result from enrollment will be stored
  here. This volume should be persistent unless you don't mind losing the key for
  your enrollment token.

## Files

The enrollment token (jwt) must be mounted into the ziti-edge-tunnel container as a volume.
The token must be in a file named `${NF_REG_NAME}.jwt` that must be in one of the
following directories:

- `/ziti-edge-tunnel`: This would be used when running in the Docker engine (or IoT Edge).
   This could be a bind mount or a docker volume.

## Examples

### Docker

The ziti-tunnel image can be used in a vanilla Docker environment.

    $ mkdir ./ziti_id
    $ cp ~/Downloads/ziti_id.jwt ./ziti_id
    $ docker pull netfoundry/ziti-edge-tunnel:latest
    $ docker run \
        --name ziti-edge-tunnel \
        --network=host \
        --cap-add=NET_ADMIN \
        --volume $(pwd)/ziti_id:/ziti-edge-tunnel \
        --device="/dev/net/tun:/dev/net/tun" \
        --env NF_REG_NAME=ziti_id \
        netfoundry/ziti-edge-tunnel:latest

Notes:

- The container that runs ziti-edge-tunnel will only be able to intercept traffic for
  other processes within the same container, unless the container uses the "host"
  network mode.
- The container requires NET_ADMIN capability to address the tun device.
- The `NF_REG_NAME` environment variable must be set to the name of the ziti
  identity that ziti-edge-tunnel will assume when connecting to the controller.
- The "/ziti-edge-tunnel" directory must be mounted on its own volume.
  - The one-time enrollment token "/ziti-edge-tunnel/${NF_REG_NAME}.jwt" must exist when
    the container is started for the first time. This is the JWT that was downloaded
    from the controller when the Ziti identity was created.
  - "/ziti-edge-tunnel/${NF_REG_NAME}.json" is created when the identity is enrolled.
    The "/ziti-edge-tunnel" volume must be persistent (that is, ${NF_REG_NAME}.json must
    endure container restarts), since the enrollment token is only valid for one
    enrollment.
