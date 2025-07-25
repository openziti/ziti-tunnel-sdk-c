ARG CMAKE_VERSION="3.26.3"

# upstream of Ubuntu Focal 20.04 LTS
FROM ubuntu:focal

ARG CMAKE_VERSION

LABEL org.opencontainers.image.authors="support@netfoundry.io"

ENV DEBIAN_FRONTEND=noninteractive
ENV GIT_DISCOVERY_ACROSS_FILESYSTEM=1
ENV TZ=UTC

USER root
WORKDIR /root/

RUN apt-get update
RUN apt-get -y install \
        autoconf automake autopoint \
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

ENV VCPKG_ROOT=/usr/local/vcpkg
# this must be set on arm. see https://learn.microsoft.com/en-us/vcpkg/users/config-environment#vcpkg_force_system_binaries
ENV VCPKG_FORCE_SYSTEM_BINARIES=yes
ENV VCPKG_BINARY_SOURCES="clear;files,/github/workspace/vcpkg_cache,readwrite"

RUN cd /usr/local \
    && git clone https://github.com/microsoft/vcpkg \
    && chmod -R ugo+rwX /usr/local/vcpkg

COPY ./entrypoint.sh /root/
ENTRYPOINT [ "/root/entrypoint.sh" ]
