ARG CMAKE_VERSION="3.22.3"

FROM ubuntu:trusty

ARG CMAKE_VERSION

LABEL org.opencontainers.image.authors="steven.broderick@netfoundry.io,kenneth.bingham@netfoundry.io"

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
        iproute2 \
        pkg-config \
        python3 \
        software-properties-common \
        zlib1g-dev \
    && add-apt-repository -y ppa:ubuntu-toolchain-r/test \
    && apt-get -y update \
    && apt-get -y install \
        gcc-9 \
        g++-9 \
    && rm -rf /var/lib/apt/lists/*

RUN update-alternatives \
        --install /usr/bin/gcc gcc /usr/bin/gcc-9 90 \
        --slave /usr/bin/g++ g++ /usr/bin/g++-9 \
        --slave /usr/bin/gcov gcov /usr/bin/gcov-9

RUN curl -L https://cmake.org/files/v${CMAKE_VERSION%.*}/cmake-${CMAKE_VERSION}-linux-x86_64.sh -o cmake.sh \
    && (bash cmake.sh --skip-license --prefix=/usr/local) \
    && rm cmake.sh

WORKDIR /github/workspace
COPY ./entrypoint.sh /root/
ENTRYPOINT [ "/root/entrypoint.sh" ]