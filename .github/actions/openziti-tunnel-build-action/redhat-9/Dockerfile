ARG CMAKE_VERSION="3.26.3"

FROM quay.io/almalinuxorg/almalinux:9.6-20250611

ARG CMAKE_VERSION

LABEL org.opencontainers.image.authors="support@netfoundry.io"

USER root
WORKDIR /root/

ENV PATH="/usr/local/:${PATH}"
ENV GIT_DISCOVERY_ACROSS_FILESYSTEM=1
ENV TZ=UTC

RUN dnf update --assumeyes --nobest \
    && dnf install --assumeyes --nobest \
        "@Development Tools" \
        dnf-plugins-core \
        iproute \
        python3 \
        systemd-devel \
        zlib-devel \
        systemd-rpm-macros \
        cmake-rpm-macros  \
        perl-FindBin perl-IPC-Cmd perl-File-Compare perl-File-Copy \
        libatomic \
    && dnf config-manager --set-enabled crb \
    && dnf install --assumeyes --nobest \
        doxygen \
        graphviz \
        git \
        json-c-devel \
        protobuf-c-devel \
        openssl-devel \
        ninja-build \
    && dnf clean all

RUN curl -sSfL https://cmake.org/files/v${CMAKE_VERSION%.*}/cmake-${CMAKE_VERSION}-linux-$(uname -m).sh -o cmake.sh \
    && (bash cmake.sh --skip-license --prefix=/usr/local) \
    && rm cmake.sh

ENV GIT_CONFIG_GLOBAL="/tmp/ziti-builder-gitconfig"

ENV VCPKG_ROOT=/usr/local/vcpkg
ENV VCPKG_BINARY_SOURCES="clear;files,/github/workspace/vcpkg_cache/archives,readwrite"
ENV VCPKG_DOWNLOADS=/github/workspace/vcpkg_cache/downloads
ENV VCPKG_INSTALLED_DIR=/github/workspace/vcpkg_cache/installed

# this must be set on arm. see https://learn.microsoft.com/en-us/vcpkg/users/config-environment#vcpkg_force_system_binaries
ENV VCPKG_FORCE_SYSTEM_BINARIES=yes

RUN cd /usr/local \
    && git clone https://github.com/microsoft/vcpkg \
    && chmod -R ugo+rwX /usr/local/vcpkg

WORKDIR /github/workspace
COPY ./entrypoint.sh /root/
ENTRYPOINT [ "/root/entrypoint.sh" ]
