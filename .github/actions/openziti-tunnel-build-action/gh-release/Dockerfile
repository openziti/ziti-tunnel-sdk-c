# use ziti-builder:v1 (Ubuntu Bionic 18.04 LTS) for older glibc (2.27)
FROM openziti/ziti-builder:v1

RUN apt-get update && apt-get -y install libpcap-dev autoconf-archive

RUN curl -sSL "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x60c317803a41ba51845e371a1e9377a2ba9ef27f" \
    | gpg --dearmor --output /usr/share/keyrings/ubuntu-toolchain-r.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/ubuntu-toolchain-r.gpg arch=amd64] http://ppa.launchpad.net/ubuntu-toolchain-r/test/ubuntu bionic main" \
    > /etc/apt/sources.list.d/ubuntu-toolchain-r.list \
    && apt-get update \
    && apt-get --yes --no-install-recommends install \
        gcc-13 \
        g++-13 \
    && apt-get --yes autoremove \
    && apt-get clean autoclean \
    && rm -fr /var/lib/apt/lists/{apt,dpkg,cache,log} /tmp/* /var/tmp/*

RUN update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-13 10 \
        && update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-13 10 \
        && update-alternatives --set gcc /usr/bin/gcc-13 \
        && update-alternatives --set g++ /usr/bin/g++-13

COPY --chmod=0755 ./entrypoint.sh /root/
ENTRYPOINT [ "/root/entrypoint.sh" ]
