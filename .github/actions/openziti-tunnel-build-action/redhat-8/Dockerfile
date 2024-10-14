ARG CMAKE_VERSION="3.26.3"

FROM rockylinux:8

ARG CMAKE_VERSION

LABEL org.opencontainers.image.authors="support@netfoundry.io"

USER root
WORKDIR /root/

ENV PATH="/usr/local/:${PATH}"
ENV GIT_DISCOVERY_ACROSS_FILESYSTEM=1
ENV TZ=UTC

RUN dnf install -y \
        "@Development Tools" \
        dnf-plugins-core \
        gcc-toolset-10 \
        gcc-toolset-10-libatomic-devel \
        iproute \
        python3 \
        systemd-devel \
        zlib-devel \
        systemd-rpm-macros \
        cmake-rpm-macros  \
        protobuf-c-devel \
        perl \
    && dnf config-manager --set-enabled powertools \
    && dnf install -y \
        doxygen \
        graphviz \
        git \
        ninja-build \
    && dnf clean all 

RUN curl -sSfL https://cmake.org/files/v${CMAKE_VERSION%.*}/cmake-${CMAKE_VERSION}-linux-$(uname -m).sh -o cmake.sh \
    && (bash cmake.sh --skip-license --prefix=/usr/local) \
    && rm cmake.sh

ENV VCPKG_ROOT=/usr/local/vcpkg
# this must be set on arm. see https://learn.microsoft.com/en-us/vcpkg/users/config-environment#vcpkg_force_system_binaries
ENV VCPKG_FORCE_SYSTEM_BINARIES=yes

RUN cd /usr/local \
    && git clone https://github.com/microsoft/vcpkg \
    && ./vcpkg/bootstrap-vcpkg.sh -disableMetrics

WORKDIR /github/workspace
COPY ./entrypoint.sh /root/
ENTRYPOINT [ "/root/entrypoint.sh" ]
