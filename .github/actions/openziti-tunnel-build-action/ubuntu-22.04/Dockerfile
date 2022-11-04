ARG CMAKE_VERSION="3.22.3"

# upstream of Ubuntu Jammy 22.04 LTS
FROM debian:bookworm

ARG CMAKE_VERSION

LABEL org.opencontainers.image.authors="support@netfoundry.io"

ENV DEBIAN_FRONTEND=noninteractive
ENV GIT_DISCOVERY_ACROSS_FILESYSTEM=1
ENV TZ=UTC

USER root
WORKDIR /root/

RUN apt-get update \
    && apt-get -y install \
        gcc-arm-linux-gnueabihf \
        g++-arm-linux-gnueabihf \
        gcc-aarch64-linux-gnu \
        crossbuild-essential-arm64 \
        crossbuild-essential-armhf \
        build-essential \
        curl \
        doxygen \
        git \
        graphviz \
        libsystemd-dev \
        iproute2 \
        pkg-config \
        python3 \
        zlib1g-dev \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN dpkg --add-architecture arm64 && dpkg --add-architecture armhf
RUN apt-get update \
    && apt-get -y install \
        libssl-dev:arm64 \
        libssl-dev:armhf \
    && rm -rf /var/lib/apt/lists/*

RUN curl -sSfL https://cmake.org/files/v${CMAKE_VERSION%.*}/cmake-${CMAKE_VERSION}-linux-$(uname -m).sh -o cmake.sh \
    && (bash cmake.sh --skip-license --prefix=/usr/local) \
    && rm cmake.sh

COPY ./entrypoint.sh /root/
ENTRYPOINT [ "/root/entrypoint.sh" ]
