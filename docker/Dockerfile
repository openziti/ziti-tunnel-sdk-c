FROM debian:bullseye-slim as fetch-ziti-artifacts
# This build stage grabs artifacts that are copied into the final image.
# It uses the same base as the final image to maximize docker cache hits.

ARG ZITI_VERSION

ARG GITHUB_BASE_URL="https://github.com/openziti"
# to fetch snapshots from the "feature-0.5" branch, set ZITI_REPO="ziti-snapshot/feature-0.5"
ARG GITHUB_REPO="ziti-tunnel-sdk-c"

WORKDIR /tmp

RUN apt-get -q update && apt-get -q install -y --no-install-recommends curl ca-certificates unzip
# workaround for `openssl rehash` not working on arm.
RUN /bin/bash -c "if ! compgen -G '/etc/ssl/certs/*.[0-9]' > /dev/null; then c_rehash /etc/ssl/certs; fi"

COPY fetch-github-releases.sh .
RUN bash ./fetch-github-releases.sh ziti-edge-tunnel

################
#
#  Main Image
#
################

FROM debian:bullseye-slim

RUN mkdir -p /usr/local/bin /etc/ssl/certs
# libsystemd: install the shared object, necessary in conjunction with      --volume "/var/run/dbus/system_bus_socket:/var/run/dbus/system_bus_socket"     to communicate with the host's dbus socket to configure systemd-resolved
# iproute2: install /sbin/ip, necessary in conjunction with    --device="/dev/net/tun:/dev/net/tun"    to up the tun device, assign routes, and assign source IP 
RUN apt-get -q update && apt-get -q install -y --no-install-recommends iproute2 libsystemd0
# Use 32-bit arm binaries on arm64 until we have 64-bit arm builds. This also affects fetch-github-releases.sh.
RUN /bin/bash -c 'if [[ "$(uname -m)" == "aarch64" ]]; then dpkg --add-architecture armhf; apt update; apt install -y libc6:armhf; fi'
COPY --from=fetch-ziti-artifacts /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs
COPY --from=fetch-ziti-artifacts /tmp/ziti-edge-tunnel /usr/local/bin
COPY ./docker-entrypoint.sh /
RUN chmod +x /docker-entrypoint.sh

ENTRYPOINT [ "/docker-entrypoint.sh" ]
CMD [ "run" ]
