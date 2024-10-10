ARG CMAKE_VERSION="3.26.3"
ARG VCPKG_VERSION="master"

# use ziti-builder:v1 (basded on ubuntu focal) for older glibc (2.27)
FROM openziti/ziti-builder:v1

COPY ./entrypoint.sh /root/
ENTRYPOINT [ "/root/entrypoint.sh" ]
