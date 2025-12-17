# use ziti-builder:v1 (Ubuntu Bionic 18.04 LTS) for older glibc (2.27)
FROM openziti/ziti-builder:v1

RUN add-apt-repository -y ppa:deadsnakes/ppa && \
    apt install -y python3.8 && \
    ln -f -s /usr/bin/python3.8 /usr/local/bin/python3

COPY --chmod=0755 ./entrypoint.sh /root/
ENTRYPOINT [ "/root/entrypoint.sh" ]
