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
  lunar|kinetic|mantic)
    UBUNTU_LTS=jammy
    ;;
  impish|hirsute|groovy)
    UBUNTU_LTS=focal
    ;;
  eoan|disco|cosmic)
    UBUNTU_LTS=bionic
    ;;
  *)
    echo "WARN: Ubuntu version: ${UBUNTU_CODENAME} not recognized, assuming latest" >&2
    UBUNTU_LTS=jammy
    ;;
esac

curl -sSLf https://get.openziti.io/tun/package-repos.gpg \
  | sudo gpg --dearmor --output /usr/share/keyrings/openziti.gpg

sudo chmod a+r /usr/share/keyrings/openziti.gpg

echo "deb [signed-by=/usr/share/keyrings/openziti.gpg] https://packages.openziti.org/zitipax-openziti-deb-stable ${UBUNTU_LTS} main" \
  | sudo tee /etc/apt/sources.list.d/openziti.list >/dev/null

sudo apt-get update
sudo apt-get install --yes ziti-edge-tunnel

# Find the most recent versioned libpcap (e.g. libpcap.so.0.8 or libpcap.so.1.10.4)
LIBPCAP=$(ldconfig -p | awk '/libpcap\.so\.[0-9]/{print $NF}' | sort -V | tail -1)

if [ -z "$LIBPCAP" ]; then
    echo "libpcap not found" >&2
    exit 1
fi

LIBDIR=$(dirname "$LIBPCAP")

# Parse soname from filename: libpcap.so.1.10.4 -> libpcap.so.1
SONAME=$(basename "$LIBPCAP" | grep -oE '^lib[^.]+\.so\.[0-9]+')

# Create soname symlink (libpcap.so.0 or libpcap.so.1) if missing
if [ -n "$SONAME" ] && [ ! -e "$LIBDIR/$SONAME" ]; then
    ln -s "$LIBPCAP" "$LIBDIR/$SONAME"
fi

# Create linker name symlink if missing
if [ ! -e "$LIBDIR/libpcap.so" ]; then
    ln -s "${SONAME:-$LIBPCAP}" "$LIBDIR/libpcap.so"
fi