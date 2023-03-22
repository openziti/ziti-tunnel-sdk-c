ARG CMAKE_VERSION="3.22.3"

# Ubuntu Bionic 18.04 LTS
FROM ubuntu:bionic

ARG CMAKE_VERSION

LABEL org.opencontainers.image.authors="support@netfoundry.io"

ENV DEBIAN_FRONTEND=noninteractive
ENV GIT_DISCOVERY_ACROSS_FILESYSTEM=1
ENV TZ=UTC

USER root
WORKDIR /root/

ENV PATH="/usr/local/:${PATH}"

RUN apt-get update \
    && apt-get -y install \
        build-essential \
        crossbuild-essential-armhf \
        crossbuild-essential-arm64 \
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

RUN curl -sSfL https://cmake.org/files/v${CMAKE_VERSION%.*}/cmake-${CMAKE_VERSION}-linux-$(uname -m).sh -o cmake.sh \
    && (bash cmake.sh --skip-license --prefix=/usr/local) \
    && rm cmake.sh

RUN dpkg --add-architecture armhf
RUN dpkg --add-architecture arm64
RUN cat <<EOF > /etc/apt/sources.list.d/crossbuild.list
deb [arch=armhf,arm64] http://ports.ubuntu.com/ bionic main restricted
deb [arch=armhf,arm64] http://ports.ubuntu.com/ bionic-updates main restricted
deb [arch=armhf,arm64] http://ports.ubuntu.com/ bionic universe
deb [arch=armhf,arm64] http://ports.ubuntu.com/ bionic-updates universe
deb [arch=armhf,arm64] http://ports.ubuntu.com/ bionic multiverse
deb [arch=armhf,arm64] http://ports.ubuntu.com/ bionic-updates multiverse
deb [arch=armhf,arm64] http://ports.ubuntu.com/ bionic-backports main restricted universe multiverse
EOF

RUN sed -Ei 's/^deb/deb [arch=amd64]/g' /etc/apt/sources.list
RUN apt-get update
RUN apt-get -y install \
    libssl-dev:armhf \
    libssl-dev:arm64

WORKDIR /github/workspace
COPY ./entrypoint.sh /root/
ENTRYPOINT [ "/root/entrypoint.sh" ]