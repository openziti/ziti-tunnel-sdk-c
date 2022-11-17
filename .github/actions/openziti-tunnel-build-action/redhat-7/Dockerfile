ARG CMAKE_VERSION="3.22.3"

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
        centos-release-scl \
        doxygen \
        graphviz \
        python3 \
        zlib-devel \
    &&  yum -y install \
        devtoolset-11 \
        devtoolset-11-libatomic-devel \
    &&  yum clean all

RUN curl -sSfL https://cmake.org/files/v${CMAKE_VERSION%.*}/cmake-${CMAKE_VERSION}-linux-$(uname -m).sh -o cmake.sh \
    && (bash cmake.sh --skip-license --prefix=/usr/local) \
    && rm cmake.sh

COPY ./entrypoint.sh /root/
ENTRYPOINT [ "/root/entrypoint.sh" ]
