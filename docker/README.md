# Run The OpenZiti Tunneler with Docker

## Host Services with Docker

The most popular way of using the Linux tunneler in Docker is to "host" an OpenZiti service, meaning as a reverse proxy and exit point from the OpenZiti network toward some target server. You can deploy the container before or after you grant it permission to start hosting the service and it will autonomously obey the OpenZiti controller.

The `openziti/ziti-host` image simply runs `ziti-edge-tunnel run-host` with the following helpful conventions for supplying an enrollment token and persisting the identity.

### Enroll and Persist Identity in a Volume

Set the enrollment token and run the container. This example saves the identity file in the persistent volume: `/ziti-edge-tunnel/ziti_id.json`.

```yaml
services:
    ziti-host:
        image: docker.io/openziti/ziti-host
        volumes:
            - ziti-host:/ziti-edge-tunnel
        environment:
            - ZITI_ENROLL_TOKEN
volumes:
    ziti-host:
```

### Use an Enrolled Identity from the Environment

You may source an existing identity from the environment.

```yaml
services:
    ziti-host:
        image: docker.io/openziti/ziti-host
        environment:
            - ZITI_IDENTITY_JSON
```

### Mount an Enrolled Identity File

You may mount an existing identity from the host's filesystem. The default path to find the identity during startup is `/ziti-edge-tunnel/ziti_id.json`. Optionally, set `ZITI_IDENTITY_BASENAME` to change the filename prefix from `ziti_id`.

```yaml
services:
    ziti-host:
        image: docker.io/openziti/ziti-host
        volumes:
            - ./ziti_id.json:/ziti-edge-tunnel/ziti_id.json
```

### Mount a Directory of Enrolled Identity Files

You may mount many existing identities from the host's filesystem. The tunneler will load all valid, readable identities at each startup. The tunneler will look for files matching `/ziti-edge-tunnel/*.json`.

```yaml
services:
    ziti-host:
        image: docker.io/openziti/ziti-host
        volumes:
            - ./identities:/ziti-edge-tunnel
```
