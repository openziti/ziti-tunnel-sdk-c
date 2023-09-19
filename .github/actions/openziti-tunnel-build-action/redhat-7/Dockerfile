ARG CMAKE_VERSION="3.26.3"

FROM docker.io/library/centos:7

ARG CMAKE_VERSION

LABEL org.opencontainers.image.authors="support@netfoundry.io"

USER root
WORKDIR /root/

ENV PATH="/usr/local/:${PATH}"
ENV GIT_DISCOVERY_ACROSS_FILESYSTEM=1
ENV TZ=UTC

RUN yum -y install \
        "@Development Tools" \
        autoconf \
        automake \
        centos-release-scl \
        doxygen \
        epel-release \
        gettext-devel \
        graphviz \
        libcap-devel \
        libtool \
        perl-IPC-Cmd \
        python3 \
        zlib-devel \
    &&  yum -y install \
        devtoolset-11 \
        devtoolset-11-libatomic-devel \
        ninja-build \
    &&  yum clean all

RUN curl -sSfL https://cmake.org/files/v${CMAKE_VERSION%.*}/cmake-${CMAKE_VERSION}-linux-$(uname -m).sh -o cmake.sh \
    && (bash cmake.sh --skip-license --prefix=/usr/local) \
    && rm cmake.sh

ENV VCPKG_ROOT=/usr/local/vcpkg
# this must be set on arm. see https://learn.microsoft.com/en-us/vcpkg/users/config-environment#vcpkg_force_system_binaries
ENV VCPKG_FORCE_SYSTEM_BINARIES=yes

RUN cd /usr/local \
    && git clone --branch 2023.06.20 https://github.com/microsoft/vcpkg \
    && ./vcpkg/bootstrap-vcpkg.sh -disableMetrics

COPY ./entrypoint.sh /root/
ENTRYPOINT [ "/root/entrypoint.sh" ]
