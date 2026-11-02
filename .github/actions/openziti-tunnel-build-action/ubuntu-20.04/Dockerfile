ARG CMAKE_VERSION="3.26.3"
# python >= 3.10 (needed by meson) isn't packaged for focal, so use a python-build-standalone build
ARG PYTHON_STANDALONE_RELEASE="20261013"
ARG PYTHON_STANDALONE_VERSION="3.12.15"
ARG PYTHON_STANDALONE_SHA256="5d546fc004fc2435fa142eb8f42ed8de5eb4725963dc22f7e6671014a80eb560"

# upstream of Ubuntu Focal 20.04 LTS
FROM ubuntu:focal

ARG CMAKE_VERSION
ARG PYTHON_STANDALONE_RELEASE
ARG PYTHON_STANDALONE_VERSION
ARG PYTHON_STANDALONE_SHA256

LABEL org.opencontainers.image.authors="support@netfoundry.io"

ENV DEBIAN_FRONTEND=noninteractive
ENV GIT_DISCOVERY_ACROSS_FILESYSTEM=1
ENV TZ=UTC

USER root
WORKDIR /root/

RUN apt-get update
RUN apt-get -y install \
        autoconf autoconf-archive automake \
        bison flex \
        gcc-arm-linux-gnueabihf \
        g++-arm-linux-gnueabihf \
        gcc-aarch64-linux-gnu \
        crossbuild-essential-arm64 \
        crossbuild-essential-armhf \
        curl zip unzip tar \
        doxygen \
        git \
        graphviz \
        libprotobuf-c-dev \
        libsystemd-dev \
        libtool \
        pkg-config \
        python3 \
        zlib1g-dev \
        ninja-build

COPY ./crossbuild.list /etc/apt/sources.list.d/crossbuild.list
RUN sed -Ei 's/^deb/deb [arch=amd64]/g' /etc/apt/sources.list
RUN dpkg --add-architecture arm64 && dpkg --add-architecture armhf
RUN apt-get update
RUN apt-get -y install \
        libprotobuf-c-dev:arm64 \
        libprotobuf-c-dev:armhf \
        zlib1g-dev:arm64 \
        zlib1g-dev:armhf \
        linux-libc-dev:arm64 \
        linux-libc-dev:armhf

# Ensure native build tools are installed correctly after multi-arch setup
RUN apt-get -y install build-essential

RUN curl -sSfL https://cmake.org/files/v${CMAKE_VERSION%.*}/cmake-${CMAKE_VERSION}-linux-$(uname -m).sh -o cmake.sh \
    && (bash cmake.sh --skip-license --prefix=/usr/local) \
    && rm cmake.sh

# newer python3 in /usr/local/bin, which is ahead of /usr/bin in PATH, so build tools that look up python3 (e.g. vcpkg
# for meson) find it. /usr/bin/python3 is left alone for distro tooling.
RUN PBS_TGZ="cpython-${PYTHON_STANDALONE_VERSION}+${PYTHON_STANDALONE_RELEASE}-x86_64-unknown-linux-gnu-install_only.tar.gz" \
    && curl -sSfL "https://github.com/astral-sh/python-build-standalone/releases/download/${PYTHON_STANDALONE_RELEASE}/${PBS_TGZ}" -o /tmp/python.tgz \
    && echo "${PYTHON_STANDALONE_SHA256}  /tmp/python.tgz" | sha256sum -c - \
    && mkdir -p /opt/python \
    && tar -xzf /tmp/python.tgz -C /opt/python --strip-components=1 \
    && rm /tmp/python.tgz \
    && PY_MINOR="${PYTHON_STANDALONE_VERSION%.*}" \
    && ln -sfvn "/opt/python/bin/python${PY_MINOR}" "/usr/local/bin/python${PY_MINOR}" \
    && ln -sfvn "/opt/python/bin/python${PY_MINOR}" /usr/local/bin/python3 \
    && /usr/local/bin/python3 --version

ENV VCPKG_ROOT=/usr/local/vcpkg
ENV VCPKG_BINARY_SOURCES="clear;files,/github/workspace/vcpkg_cache,readwrite"

RUN cd /usr/local \
    && git clone https://github.com/microsoft/vcpkg \
    && chmod -R ugo+rwX /usr/local/vcpkg

COPY ./entrypoint.sh /root/
ENTRYPOINT [ "/root/entrypoint.sh" ]
