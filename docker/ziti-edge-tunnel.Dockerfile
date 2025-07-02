FROM registry.access.redhat.com/ubi10/ubi-minimal

ARG ARTIFACTS_DIR=./build
ARG DOCKER_BUILD_DIR=.
# e.g. linux
ARG TARGETOS
# e.g. arm64
ARG TARGETARCH

### Required OpenShift Labels 
LABEL name="openziti/ziti-edge-tunnel" \
      maintainer="developers@openziti.org" \
      vendor="NetFoundry" \
      summary="OpenZiti Tunneler" \
      description="Configure a proxy and nameserver for OpenZiti Services"

USER root

### add licenses to this directory
RUN mkdir -m0755 /licenses
COPY ${DOCKER_BUILD_DIR}/LICENSE-Apache /licenses/apache.txt

### Add necessary Red Hat repos and packages
# installing util-linux adds 20MB to the image size and doesn't seem worthwhile just for the mountpoint command...
RUN INSTALL_PKGS="iproute procps shadow-utils jq" \
    && microdnf -y update --setopt=install_weak_deps=0 --setopt=tsflags=nodocs \
    && microdnf -y install --setopt=install_weak_deps=0 --setopt=tsflags=nodocs ${INSTALL_PKGS}

COPY ${ARTIFACTS_DIR}/${TARGETARCH}/${TARGETOS}/ziti-edge-tunnel /usr/local/bin/
COPY ${DOCKER_BUILD_DIR}/docker-entrypoint.sh /
RUN chmod +x /docker-entrypoint.sh
RUN mkdir -m0777 /ziti-edge-tunnel
RUN groupadd --system --gid 2171 ziti

RUN UNINSTALL_PKGS="shadow-utils" \
    && microdnf -y remove ${UNINSTALL_PKGS}

ENTRYPOINT [ "/docker-entrypoint.sh" ]
CMD [ "run" ]
