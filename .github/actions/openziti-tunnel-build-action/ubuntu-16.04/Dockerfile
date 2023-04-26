ARG CMAKE_VERSION="3.22.3"

FROM ubuntu:xenial

ARG CMAKE_VERSION

LABEL org.opencontainers.image.authors="support@netfoundry.io"

ENV DEBIAN_FRONTEND=noninteractive
ENV GIT_DISCOVERY_ACROSS_FILESYSTEM=1
ENV TZ=UTC

USER root
WORKDIR /root/

ENV PATH="/usr/local/:${PATH}"

RUN apt-get -y update \
    && apt-get -y install \
        build-essential \
        curl \
        doxygen \
        git \
        graphviz \
        pkg-config \
        python3 \
        libssl-dev \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

RUN curl -sSfL https://cmake.org/files/v${CMAKE_VERSION%.*}/cmake-${CMAKE_VERSION}-linux-$(uname -m).sh -o cmake.sh \
    && (bash cmake.sh --skip-license --prefix=/usr/local) \
    && rm cmake.sh

ENV VCPKG_ROOT=/usr/local/vcpkg
# this must be set on arm. see https://learn.microsoft.com/en-us/vcpkg/users/config-environment#vcpkg_force_system_binaries
ENV VCPKG_FORCE_SYSTEM_BINARIES=yes

RUN cd /usr/local \
    && git config --global advice.detachedHead false \
    && git clone --branch 2023.04.15 https://github.com/microsoft/vcpkg \
    && ./vcpkg/bootstrap-vcpkg.sh -disableMetrics \

WORKDIR /github/workspace
COPY ./entrypoint.sh /root/
ENTRYPOINT [ "/root/entrypoint.sh" ]
