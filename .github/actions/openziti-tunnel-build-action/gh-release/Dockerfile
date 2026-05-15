# use ziti-builder:v1 (Ubuntu Bionic 18.04 LTS) for older glibc (2.27)
FROM openziti/ziti-builder:v1

RUN apt-get update && apt-get -y install libpcap-dev

COPY --chmod=0755 ./entrypoint.sh /root/
ENTRYPOINT [ "/root/entrypoint.sh" ]
