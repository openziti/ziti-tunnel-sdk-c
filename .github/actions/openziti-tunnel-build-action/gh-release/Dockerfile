# use ziti-builder:v1 (Ubuntu Bionic 18.04 LTS) for older glibc (2.27)
FROM openziti/ziti-builder:v1

COPY --chmod=0755 ./entrypoint.sh /root/
ENTRYPOINT [ "/root/entrypoint.sh" ]
