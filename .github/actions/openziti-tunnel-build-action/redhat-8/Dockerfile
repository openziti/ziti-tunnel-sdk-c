FROM quay.io/rockylinux/rockylinux:8

LABEL org.opencontainers.image.authors="steven.broderick@netfoundry.io,kenneth.bingham@netfoundry.io"

USER root
WORKDIR /root/

ENV PATH="/usr/local/:${PATH}"
ENV GIT_DISCOVERY_ACROSS_FILESYSTEM=1
ENV TZ=UTC

RUN dnf install -y \
        "@Development Tools" \
        cmake \
        dnf-plugins-core \
        gcc-toolset-10 \
        gcc-toolset-10-libatomic-devel \
        iproute \
        python3 \
        systemd-devel \
        zlib-devel \
        systemd-rpm-macros \
        cmake-rpm-macros  \
    && dnf config-manager --set-enabled powertools \
    && dnf install -y \
        doxygen \
        graphviz \
        git \
    && dnf clean all 

    
WORKDIR /github/workspace
COPY ./entrypoint.sh /root/
ENTRYPOINT [ "/root/entrypoint.sh" ]
