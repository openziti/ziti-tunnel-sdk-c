# this builds docker.io/openziti/ziti-edge-tunnel
FROM registry.access.redhat.com/ubi8/ubi as fetch-ziti-artifacts
# This build stage grabs artifacts that are copied into the final image.
# It uses the same base as the final image to maximize docker cache hits.

ARG ZITI_VERSION

ARG GITHUB_BASE_URL
ARG GITHUB_REPO

WORKDIR /tmp

### Add necessary Red Hat repos and packages
RUN REPOLIST=ubi-8-baseos-rpms \
    INSTALL_PKGS="curl unzip" && \
    yum -y update-minimal --disablerepo "*" --enablerepo ${REPOLIST} --setopt=tsflags=nodocs \
      --security --sec-severity=Important --sec-severity=Critical && \
    yum -y install --disablerepo "*" --enablerepo ${REPOLIST} --setopt=tsflags=nodocs ${INSTALL_PKGS}

COPY fetch-github-releases.sh .
RUN bash ./fetch-github-releases.sh ziti-edge-tunnel

################
#
#  Main Image
#
################

FROM registry.access.redhat.com/ubi8/ubi

### Required OpenShift Labels 
LABEL name="openziti/ziti-edge-tunnel" \
      maintainer="developers@openziti.org" \
      vendor="NetFoundry" \
      summary="OpenZiti tunneler" \
      description="Configure a forward proxy and nameserver for OpenZiti Services"

### add licenses to this directory
RUN mkdir -m0755 /licenses
COPY ./LICENSE-Apache /licenses/apache.txt

### Add necessary Red Hat repos and packages
RUN REPOLIST=ubi-8-baseos-rpms \
    INSTALL_PKGS="iproute procps" && \
    yum -y update-minimal --disablerepo "*" --enablerepo ${REPOLIST} --setopt=tsflags=nodocs \
      --security --sec-severity=Important --sec-severity=Critical && \
    yum -y install --disablerepo "*" --enablerepo ${REPOLIST} --setopt=tsflags=nodocs ${INSTALL_PKGS}

RUN mkdir -p /usr/local/bin
COPY --from=fetch-ziti-artifacts /tmp/ziti-edge-tunnel /usr/local/bin
COPY ./docker-entrypoint.sh /
RUN chmod +x /docker-entrypoint.sh
RUN mkdir -m0777 /ziti-edge-tunnel
USER root

ENTRYPOINT [ "/docker-entrypoint.sh" ]
CMD [ "run" ]
