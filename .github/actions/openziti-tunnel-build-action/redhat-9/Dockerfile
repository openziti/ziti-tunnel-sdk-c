ARG CMAKE_VERSION="3.26.3"
ARG VCPKG_VERSION="2024.08.23"

FROM rockylinux:9

ARG CMAKE_VERSION
ARG VCPKG_VERSION

LABEL org.opencontainers.image.authors="support@netfoundry.io"

USER root
WORKDIR /root/

ENV PATH="/usr/local/:${PATH}"
ENV GIT_DISCOVERY_ACROSS_FILESYSTEM=1
ENV TZ=UTC

RUN dnf install -y \
        "@Development Tools" \
        autoconf \
        automake \
        cmake-rpm-macros  \
        dnf-plugins-core \
        gettext-devel \
        iproute \
        libacl-devel \
        libatomic \
        libcap-devel \
        libtool \
        openssl-devel \
        perl-File-Compare \
        perl-File-Copy \
        perl-FindBin \
        perl-IPC-Cmd \
        python3 \
        systemd-devel \
        systemd-rpm-macros \
        zlib-devel \
    && dnf config-manager --set-enabled crb \
    && dnf install -y \
        doxygen \
        git \
        graphviz \
        ninja-build \
    && dnf clean all

RUN curl -sSfL https://cmake.org/files/v${CMAKE_VERSION%.*}/cmake-${CMAKE_VERSION}-linux-$(uname -m).sh -o cmake.sh \
    && (bash cmake.sh --skip-license --prefix=/usr/local) \
    && rm cmake.sh

ENV GIT_CONFIG_GLOBAL="/tmp/ziti-builder-gitconfig"

ENV VCPKG_ROOT=/usr/local/vcpkg
# this must be set on arm. see https://learn.microsoft.com/en-us/vcpkg/users/config-environment#vcpkg_force_system_binaries
ENV VCPKG_FORCE_SYSTEM_BINARIES=yes

RUN cd /usr/local \
    && git clone --branch "${VCPKG_VERSION}" https://github.com/microsoft/vcpkg \
    && ./vcpkg/bootstrap-vcpkg.sh -disableMetrics \
    && chmod -R ugo+rwX /usr/local/vcpkg

WORKDIR /github/workspace
COPY ./entrypoint.sh /root/
ENTRYPOINT [ "/root/entrypoint.sh" ]
