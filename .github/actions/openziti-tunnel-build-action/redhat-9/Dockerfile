ARG CMAKE_VERSION="3.22.3"

FROM rockylinux:9

ARG CMAKE_VERSION

LABEL org.opencontainers.image.authors="support@netfoundry.io"

USER root
WORKDIR /root/

ENV PATH="/usr/local/:${PATH}"
ENV GIT_DISCOVERY_ACROSS_FILESYSTEM=1
ENV TZ=UTC

RUN dnf install -y \
        "@Development Tools" \
        cmake \
        dnf-plugins-core \
        iproute \
        python3 \
        systemd-devel \
        zlib-devel \
        systemd-rpm-macros \
        cmake-rpm-macros  \
        openssl-devel \
        libatomic \
    && dnf config-manager --set-enabled crb \
    && dnf install -y \
        doxygen \
        graphviz \
        git \
    && dnf clean all 

RUN curl -sSfL https://cmake.org/files/v${CMAKE_VERSION%.*}/cmake-${CMAKE_VERSION}-linux-$(uname -m).sh -o cmake.sh \
    && (bash cmake.sh --skip-license --prefix=/usr/local) \
    && rm cmake.sh

WORKDIR /github/workspace
COPY ./entrypoint.sh /root/
ENTRYPOINT [ "/root/entrypoint.sh" ]
