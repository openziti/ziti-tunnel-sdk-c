# Run The OpenZiti Tunneler with Docker

## Contents

- [Conventions](#conventions)
- Use cases:
  - [Hosting OpenZiti services](#use-case-hosting-openziti-services)
  - [Connecting to OpenZiti services with an intercepting proxy](#use-case-intercepting-proxy-and-nameserver)

## Conventions

### Configuring the OpenZiti Identity

It is necessary to supply an identity enrollment token or an enrolled identity configuration JSON to the container as a volume-mounted file or as environment variables. The following variable, volumes, and files are common to both container images described below.

#### Configuration with Environment Variable

- `ZITI_IDENTITY_JSON`: This is the identity represented as JSON. This variable overrides other methods of supplying the identity JSON. It is not advisable to mount a volume on the container filesystem when using this method because the identity is written to a temporary file and will cause an error if the file already exists.

#### Configuration with Files from Mounted Volume

You may bind a host directory to the container filesystem in `/ziti-edge-tunnel` to supply the token JWT file or configuration JSON file. If you provide a token JWT file, the entrypoint script will enroll the identity during container startup. The entrypoint script will write the identity configuration JSON file in the same directory with a filename like `${ZITI_IDENTITY_BASENAME}.json`.

- `ZITI_IDENTITY_BASENAME`: the file basename (without the filename suffix) of the enrollment (.jwt) and identity (.json) files the tunneler will use
- `ZITI_ENROLL_TOKEN`: Optionally, you may supply the enrollment token JWT as a string if `${ZITI_IDENTITY_BASENAME}.jwt` is not mounted
- `ZITI_IDENTITY_WAIT`: Optionally, you may configure the container to wait max seconds for the JWT or JSON file to appear in the mounted volume

## Use Case: Hosting OpenZiti Services

This use case involves deploying the OpenZiti tunneler as a reverse proxy to publish regular network servers to your OpenZiti Network. You may locate the published servers in a Docker bridge network (use network mode `bridge`) or the Docker host's network (use network mode `host`). See [the Linux tunneler doc](https://docs.openziti.io/docs/reference/tunnelers/linux/) for general info about the OpenZiti tunneler. Use the `openziti/ziti-host` container image for this case.

### Container Image `openziti/ziti-host`

This image runs `ziti-edge-tunnel run-host` to invoke the hosting-only mode of the tunneler. The main difference from the parent image (`openziti/ziti-edge-tunnel`) is the command argument and run-as user. This container runs as "nobody" and doesn't require special privileges.

#### Image Tags for `openziti/ziti-host`

The `openziti/ziti-host` image is published in Docker Hub and automatically updated with new releases. You may subscribe to `:latest` (default) or pin a version for stability e.g. `:0.19.11`.

#### Dockerfile for `openziti/ziti-host`

The Dockerfile for `openziti/ziti-host` is [./Dockerfile.ziti-host](Dockerfile.ziti-host).

#### Hosting an OpenZiti Service with `openziti/ziti-host`

Publish servers that are reachable on the Docker host's network, e.g., `tcp:localhost:54321`:

```bash
# identity file on Docker host is mounted in container: /opt/openziti/etc/identities/my-ziti-identity.json
docker run \
  --name ziti-host \
  --rm \
  --network=host \
  --env ZITI_IDENTITY_BASENAME="my-ziti-identity" \
  --volume /opt/openziti/etc/identities:/ziti-edge-tunnel \
  openziti/ziti-host
```

Publish servers inside the same Docker bridge network, e.g., `tcp:my-docker-service:80`:

```bash
# identity file on Docker host is stuffed in env var: /opt/openziti/etc/identities/my-ziti-identity.json
docker run \
  --name ziti-host \
  --rm \
  --network=my-docker-bridge \
  --env ZITI_IDENTITY_JSON="$(< /opt/openziti/etc/identities/my-ziti-identity.json)" \
  openziti/ziti-host
```

This example uses [the included Docker Compose project](docker-compose.yml) to illustrate publishing a server container to your OpenZiti Network.

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

1. Create a service associating the two configs with a role attribute like "#HelloServices."
1. Create an identity for your client tunneler named "MyClient" and load the identity.
1. Create an identity named "DockerHost" and download the enrollment token in the same directory as `docker-compose.yml`, i.e., "DockerHost.jwt."
1. Create a Bind service policy assigning "#HelloServices" to be bound by "@DockerHost."
1. Create a Dial service policy granting access to "#HelloServices" to your client tunneler's identity "@MyClient."
1. Run the demo server

    ```bash
    docker-compose up --detach hello
    ```

1. Run the tunneler

    ```bash
    ZITI_IDENTITY_JSON="$(< /tmp/my-ziti-id.json)" docker-compose up --detach ziti-host
    # debug
    ZITI_IDENTITY_JSON="$(< /tmp/my-ziti-id.json)" docker-compose run ziti-host run-host --verbose=4
    ```

1. Access the demo server via your OpenZiti Network: [http://hello-docker.ziti](http://hello-docker.ziti)

#### Troubleshooting `openziti/ziti-host`

You may pass additional args by supplying the `run-host` mode and args when the container is run.

```bash
docker run \
  --name ziti-host \
  --rm \
  --network=my-docker-bridge \
  --env ZITI_IDENTITY_JSON="$(< /opt/openziti/etc/identities/my-ziti-identity.json)" \
  openziti/ziti-host \
    run-host --verbose=4
```

#### Docker Compose Examples for `openziti/ziti-host`

Get a single, enrolled identity configuration from an environment variable. You could define the variable with an `.env` file in the same directory as `docker-compose.yml`.

```yaml
version: "3.9"
services:
    ziti-host:
        image: openziti/ziti-host
        environment:
            - ZITI_IDENTITY_JSON
```

Configure a single, enrolled identity from the host filesystem directory in the same directory as `docker-compose.yml`.

In this example, the file `ziti_id.jwt` exists and is used to enroll on the first run, producing `ziti_id.json`, the identity configuration file. Subsequent runs will use only the enrolled identity's JSON configuration file.

```yaml
version: "3.9"
services:
    ziti-host:
        image: openziti/ziti-host
        volumes:
            - .:/ziti-edge-tunnel
        environment:
            - ZITI_IDENTITY_BASENAME=ziti_id
```

Configure all enrolled identities from a named volume.

This example loads all files named *.json from the mounted volume.

```yaml
version: "3.9"
services:
    ziti-host:
        image: openziti/ziti-host
        volumes:
            - ziti-identities:/ziti-edge-tunnel
volumes:
    ziti-identities:
```

Enroll a single identity with a token from an environment variable and store in a named volume.

```yaml
version: "3.9"
services:
    ziti-host:
        image: openziti/ziti-host
        volumes:
            - ziti-identity:/ziti-edge-tunnel
        environment:
            - ZITI_IDENTITY_BASENAME=ziti_id
            - ZITI_ENROLL_TOKEN=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbSI6Im90dCIsImV4cCI6MTY3MDAwEFQ2NywiaXNzIjoiaHR0cHM6Ly83Y2U3ZTQyNC02YTkyLTRmZjItOTQ1OS1lYmJiYTMyMzQ2ZmEucHJvZHVjdGlvbi5uZXRmb3VuZHJ5LmlvOjQ0MyIsImp0aSI6ImQ0YjczZjFlLTRkOWEtNDk0ZC04NGQxLTQ2OWE1MGQyYzhmMCIsInN1YiI6ImdXdkQwaTd5RDkifQ.R5t2hoH0W1vJUn78_O8azoJ05FWLLSh6J3Q1XaDOidaYgDOWcLm7YiV99rymnjSjRC86IjNsAyZK678_D2dqyefR3VBI8LepamZ5jVSAcDFCF3Swk_jszcHDqcYs2YCucr6qrwsv8NTqEdUAJ8NVOiRaZbGhSuBvXTmWilCkCLcL7R4tXpIHakM_2WA4_tmwdbN8i7SGPPAB6pZOK_xDW10nBjg5Fe3Of_-53Gd-3swm9D3Yms1iIPBfMIQUWNzYaOCBa8UvGo8d9JjvJKgTlkMwZHL3hayzAuVEXoR1-LbA1t1Nhd8FgjvuL-YxN0XLaA3koL-FijL7ehWZoyUYPuO3xi63SQpbO-oDtX89jvGLMVercZBscXQsmCkDcj8OAnTb3Czb8HmsHgfydqvT6epUNFxFe_fSGz-CuGIuFBQwygfpBriGBnwVk8dnIJt7Wl75jPR8v-NImIIv1dKCI_ZajlsJ5l8D4OGnj76pBs3Wu7Hq1zxAbJ8HPJmi_ywTHAHVJVghifRTIR6_SyfeZGsHDY9s8YH5ErYvarBvMxwPCmjMMY3SKM_YOPG0u1c-KKByS3m7x7qia6P1ShWwGkbMmY722iFeVvoGN7SD51CkZiqWHClhBtdDv6_1K7y62KEmiX0D4YHXoikNqMCoPwa4yKyDRzoO8DKcAzaVRRg
volumes:
    ziti-identity:
```

#### Kubernetes Deployments for `openziti/ziti-host`

Refer to [the workload tunneling guides for Kubernetes](https://docs.openziti.io/docs/guides/kubernetes/workload-tunneling/).

## Use Case: Intercepting Proxy and Nameserver

This use case involves deploying the OpenZiti tunneler as an intercepting proxy with a built-in nameserver. Use the `openziti/ziti-edge-tunnel` container image for this case.

The "run" mode requires elevated privileges to configure the OS with a DNS resolver and IP routes.

### Container Image `openziti/ziti-edge-tunnel`

This image runs `ziti-edge-tunnel run`, the intercepting proxy mode of the tunneler. The Red Hat 8 Universal Base Image (UBI) is the base image of this container.

See [the Linux tunneler doc](https://docs.openziti.io/docs/reference/tunnelers/linux/) for general info about the OpenZiti tunneler.

#### Tags for `openziti/ziti-edge-tunnel`

The container image `openziti/ziti-edge-tunnel` is published in Docker Hub and automatically updated with new releases. You may subscribe to `:latest` (default) or pin a version for stability, e.g., `:0.19.11`.

#### Dockerfile for `openziti/ziti-edge-tunnel`

The Dockerfile for `openziti/ziti-edge-tunnel` is [./Dockerfile.base](Dockerfile.base).

#### Accessing OpenZiti Services with `openziti/ziti-edge-tunnel`

Intercepting proxy `run` mode captures DNS names and layer-4 traffic that match authorized destinations.

```bash
# current directory contains enrollment token file ziti_id.jwt
docker run \
    --name ziti-tun \
    --network host \
    --privileged \
    --volume ${PWD}:/ziti-edge-tunnel/ \
    --volume "/var/run/dbus/system_bus_socket:/var/run/dbus/system_bus_socket" \
    --device "/dev/net/tun:/dev/net/tun" \
    --env ZITI_IDENTITY_BASENAME=ziti_id \
    openziti/ziti-edge-tunnel
```

#### Troubleshooting `openziti/ziti-edge-tunnel`

You may pass additional args by supplying the `run` mode followed by args when the container is run.

```bash
docker run \
    --name ziti-tun \
    --network host \
    --privileged \
    --volume ${PWD}:/ziti-edge-tunnel/ \
    --volume "/var/run/dbus/system_bus_socket:/var/run/dbus/system_bus_socket" \
    --device "/dev/net/tun:/dev/net/tun" \
    --env ZITI_IDENTITY_BASENAME=ziti_id \
    openziti/ziti-edge-tunnel \
      run --verbose=4
```

#### Docker Compose Examples for `openziti/ziti-edge-tunnel`

This example uses [the Docker Compose project](docker-compose.yml) included in this repo.

```bash
# enrolled identity file ziti_id.json is in the same directory as docker-compose.yml
ZITI_IDENTITY_BASENAME=ziti_id docker-compose run ziti-tun
```

This example uses a single, enrolled identity configuration file `ziti_id.json` in the same directory as `docker-compose.yml`.

```yaml
version: "3.9"
services:
    ziti-tun:
        image: openziti/ziti-edge-tunnel
        devices:
            - /dev/net/tun:/dev/net/tun
        volumes:
            - .:/ziti-edge-tunnel
            - /var/run/dbus/system_bus_socket:/var/run/dbus/system_bus_socket
        environment:
            - ZITI_IDENTITY_BASENAME=ziti_id
            - PFXLOG_NO_JSON=true              # suppress JSON logging
        network_mode: host
        privileged: true
```

#### Kubernetes Deployments for `openziti/ziti-edge-tunnel`

Refer to [the workload tunneling guides for Kubernetes](https://docs.openziti.io/docs/guides/kubernetes/workload-tunneling/).
