FROM ubuntu:focal

LABEL org.opencontainers.image.authors="steven.broderick@netfoundry.io,kenneth.bingham@netfoundry.io"

ENV DEBIAN_FRONTEND=noninteractive
ENV GIT_DISCOVERY_ACROSS_FILESYSTEM=1
ENV TZ=UTC

USER root
WORKDIR /root/

RUN apt-get -y update \
    && apt-get -y install \
        build-essential \
        cmake \
        curl \
        doxygen \
        git \
        graphviz \
        libsystemd-dev \
        iproute2 \
        pkg-config \
        python3 \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

COPY ./entrypoint.sh /root/
ENTRYPOINT [ "/root/entrypoint.sh" ]