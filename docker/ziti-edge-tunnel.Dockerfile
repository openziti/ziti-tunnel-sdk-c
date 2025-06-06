FROM almalinux:9 AS opensc

ARG OPENSC_VERSION=0.26.1

ENV OPENSC_VERSION=${OPENSC_VERSION} \
    OPENSC_SOURCES=/tmp/opensc

RUN dnf install -y dnf-plugins-core && \
    dnf config-manager --set-enabled crb && \
    dnf update -y
RUN dnf install -y \
        readline-devel \
        openssl-devel \
        libxslt \
        docbook-style-xsl \
        pcsc-lite-devel \
        automake \
        autoconf \
        libtool \
        git \
        gcc \
        make \
        which

RUN git clone https://github.com/OpenSC/OpenSC.git ${OPENSC_SOURCES}
WORKDIR ${OPENSC_SOURCES}

RUN git checkout ${OPENSC_VERSION} -b ${OPENSC_VERSION} \
    && ./bootstrap \
    && ./configure --prefix=/usr/local --sysconfdir=/etc/opensc \
    && make \
    && make install

FROM almalinux:9 AS yubikey

ARG YUBIKEY_VERSION=yubico-piv-tool-2.7.1

ENV YUBIKEY_VERSION=${YUBIKEY_VERSION} \
    YUBIKEY_SOURCES=/tmp/yubikey

RUN dnf install -y dnf-plugins-core && \
    dnf config-manager --set-enabled crb && \
    dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm && \
    dnf update -y
RUN dnf install -y \
    cmake \
    libtool \
    openssl-devel \
    pkg-config \
    check \
    check-devel \
    pcsc-lite-devel \
    help2man \
    git \
    gcc \
    gcc-c++ \
    gengetopt \
    make \
    which \
    zlib-devel \
    cmake3

RUN git clone https://github.com/Yubico/yubico-piv-tool.git ${YUBIKEY_SOURCES}
WORKDIR ${YUBIKEY_SOURCES}

RUN git checkout ${YUBIKEY_VERSION} -b ${YUBIKEY_VERSION} \
    && mkdir -p build && cd build \
    && cmake3 .. \
    && make \
    && make install

FROM registry.access.redhat.com/ubi9/ubi-minimal AS runner

COPY --from=opensc /usr/local /usr/local
COPY --from=yubikey /usr/local /usr/local

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
RUN INSTALL_PKGS="iproute procps shadow-utils jq openssl-pkcs11" \
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
