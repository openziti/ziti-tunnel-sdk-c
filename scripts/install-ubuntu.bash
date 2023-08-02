#!/usr/bin/env bash

set -euxo pipefail

source /etc/os-release
[[ -n ${UBUNTU_CODENAME:-} ]] || {
  echo "Unable to determine Ubuntu version" >&2
  exit 1
}

case ${UBUNTU_CODENAME} in 
  jammy|focal|bionic)
    UBUNTU_LTS=${UBUNTU_CODENAME}
    ;;
  lunar|kinetic)
    UBUNTU_LTS=jammy
    ;;
  impish|hirsute|groovy)
    UBUNTU_LTS=focal
    ;;
  eoan|disco|cosmic)
    UBUNTU_LTS=bionic
    ;;
  *)
    echo "Unsupported Ubuntu version: ${UBUNTU_CODENAME}" >&2
    exit 1
    ;;
esac

curl -sSLf https://get.openziti.io/tun/package-repos.gpg \
  | sudo gpg --dearmor --output /usr/share/keyrings/openziti.gpg

echo "deb [signed-by=/usr/share/keyrings/openziti.gpg] https://packages.openziti.org/zitipax-openziti-deb-stable ${UBUNTU_LTS} main" \
  | sudo tee /etc/apt/sources.list.d/openziti.list >/dev/null

sudo apt update
sudo apt install -y ziti-edge-tunnel
