ARG CMAKE_VERSION="3.26.3"
ARG VCPKG_VERSION="2024.08.23"

# Ubuntu Jammy 22.04 LTS
FROM ubuntu:jammy

ARG CMAKE_VERSION
ARG VCPKG_VERSION

LABEL org.opencontainers.image.authors="support@netfoundry.io"

ENV DEBIAN_FRONTEND=noninteractive
ENV GIT_DISCOVERY_ACROSS_FILESYSTEM=1
ENV TZ=UTC

USER root
WORKDIR /root/

RUN apt-get update \
    && apt-get -y install \
        autoconf \
        automake \
        autopoint \
        build-essential \
        crossbuild-essential-arm64 \
        crossbuild-essential-armhf \
        curl zip unzip tar \
        doxygen \
        g++-arm-linux-gnueabihf \
        gcc-aarch64-linux-gnu \
        gcc-arm-linux-gnueabihf \
        git \
        graphviz \
        libcap-dev \
        libssl-dev \
        libsystemd-dev \
        libtool \
        ninja-build \
        pkg-config \
        python3 \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

COPY ./crossbuild.list /etc/apt/sources.list.d/crossbuild.list
RUN sed -Ei 's/^deb/deb [arch=amd64]/g' /etc/apt/sources.list
RUN dpkg --add-architecture arm64 && dpkg --add-architecture armhf
RUN apt-get update \
    && apt-get -y install \
        libcap-dev:armhf \
        libcap-dev:arm64 \
        libssl-dev:arm64 \
        libssl-dev:armhf \
        zlib1g-dev:arm64 \
        zlib1g-dev:armhf \
    && rm -rf /var/lib/apt/lists/*

RUN curl -sSfL "https://cmake.org/files/v${CMAKE_VERSION%.*}/cmake-${CMAKE_VERSION}-linux-$(uname -m).sh" -o cmake.sh \
    && (bash cmake.sh --skip-license --prefix=/usr/local) \
    && rm cmake.sh

ENV VCPKG_ROOT=/usr/local/vcpkg
# this must be set on arm. see https://learn.microsoft.com/en-us/vcpkg/users/config-environment#vcpkg_force_system_binaries
ENV VCPKG_FORCE_SYSTEM_BINARIES=yes

RUN cd /usr/local \
    && git config --global advice.detachedHead false \
    && git clone --branch "${VCPKG_VERSION}" https://github.com/microsoft/vcpkg \
    && ./vcpkg/bootstrap-vcpkg.sh -disableMetrics

COPY ./entrypoint.sh /root/
ENTRYPOINT [ "/root/entrypoint.sh" ]
