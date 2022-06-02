ARG CMAKE_VERSION="3.22.3"

FROM quay.io/centos/centos:7

ARG CMAKE_VERSION

LABEL org.opencontainers.image.authors="steven.broderick@netfoundry.io,kenneth.bingham@netfoundry.io"

USER root
WORKDIR /root/

ENV PATH="/usr/local/:${PATH}"
ENV GIT_DISCOVERY_ACROSS_FILESYSTEM=1
ENV TZ=UTC

RUN yum -y install \
        "@Development Tools" \
        centos-release-scl \
        doxygen \
        graphviz \
        python3 \
        zlib-devel \
        openssl-devel \
    &&  yum -y install \
        devtoolset-11 \
        devtoolset-11-libatomic-devel \
    &&  yum clean all

RUN curl -L https://cmake.org/files/v${CMAKE_VERSION%.*}/cmake-${CMAKE_VERSION}-linux-x86_64.sh -o cmake.sh \
    && (bash cmake.sh --skip-license --prefix=/usr/local) \
    && rm cmake.sh

COPY ./entrypoint.sh /root/
ENTRYPOINT [ "/root/entrypoint.sh" ]
