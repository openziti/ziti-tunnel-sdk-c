# this builds docker.io/openziti/ziti-host
ARG ZITI_EDGE_TUNNEL_IMAGE="docker.io/openziti/ziti-edge-tunnel"
ARG ZITI_EDGE_TUNNEL_TAG="latest"

# this builds docker.io/openziti/ziti-host
FROM ${ZITI_EDGE_TUNNEL_IMAGE}:${ZITI_EDGE_TUNNEL_TAG}

### Required OpenShift Labels 
LABEL name="openziti/ziti-host" \
      maintainer="developers@openziti.org" \
      vendor="NetFoundry" \
      summary="OpenZiti Hosting Tunneler" \
      description="Configure a reverse proxy for OpenZiti Services"

USER nobody

ENTRYPOINT [ "/docker-entrypoint.sh" ]
CMD [ "run-host" ]
