# Run The OpenZiti Tunneler with Docker

> [!IMPORTANT]
> Persistent, writable volumes are necessary for the tunneler to manage identity files, e.g., certificate renewal.

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

You may source an existing identity from an environment variable. The value will be written to the mounted volume and the variable ignored thereafter. The identity file in the mounted volume will be overwritten when the certificate is automatically renewed.

```yaml
services:
    ziti-host:
        image: docker.io/openziti/ziti-host
        volumes:
            - ziti-host:/ziti-edge-tunnel
        environment:
            - ZITI_IDENTITY_JSON
volumes:
    ziti-host:
```

### Mount a Writable Identity File

You may mount an existing, writable identity file from the host's filesystem. The default path in the container's filesystem is `/ziti-edge-tunnel/ziti_id.json`. Optionally, set `ZITI_IDENTITY_BASENAME` to another filename prefix (default: `ziti_id`). Ensure the run-as UID:GID has permission to read and write the file so that the tunneler can automatically renew its certificate.

```bash
$ ls -ln ziti_id.json
-rw-r--r-- 1 1001 1001 123456789 Jan 1 12:34 ziti_id.json
```

```yaml
services:
    ziti-host:
        user: "1001:1001"
        image: docker.io/openziti/ziti-host
        volumes:
            - ./ziti_id.json:/ziti-edge-tunnel/ziti_id.json
```

### Mount a Writable Directory of Identity Files

You may mount a writable directory containing existing identities from the host's filesystem. The tunneler will load all valid, readable identities named `/ziti-edge-tunnel/*.json` at startup. Ensure the run-as UID:GID has permission to read, write, and list the files so that the tunneler can automatically renew its certificates.

```bash
$ ls -lna identities
drwx------    1 1001 1001 4096 Apr 22 21:03 .
drwx-----x    2 1001 1001 4096 Apr 10 09:58 ..
-rw-r--r--    1 1001 1001 6789 Jan  1 12:34 ziti_id.json
-rw-r--r--    1 1001 1001 6789 Jan  1 12:34 ziti_id2.json
```

```yaml
services:
    ziti-host:
        user: "1001:1001"
        image: docker.io/openziti/ziti-host
        volumes:
            - ./identities:/ziti-edge-tunnel
```
