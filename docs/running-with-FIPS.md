# Using the Unix Tunneler in FIPS mode.

This guide applies to Linux and Darwin (macOS).

## Overview

1. Install a release package or build `ziti-edge-tunnel` from source
2. Install the OpenSSL FIPS module
3. Configure the OpenSSL FIPS module
4. Run the Tunneler

## Acquiring the Tunneler Binary

You may install a release package on Debian or RedHat Linux, or build `ziti-edge-tunnel` from source.

### Install a Release Package

A release package is available for Ubuntu 22.04 and later LTS
releases that are FIPS certified through Ubuntu Pro, and for RedHat 9.

The package can be installed by following the installation instructions for those distributions:

- [Ubuntu 22.04 Jammy Jellyfish](https://openziti.io/docs/reference/tunnelers/linux/debian-package)
- [RedHat 9](https://openziti.io/docs/reference/tunnelers/linux/redhat-package)

### Build from Source

If a package is not available for your Linux distribution, or if you're targeting Darwin (macOS), this section describes how to build and run ziti-edge-tunnel in FIPS mode.

Using FIPS mode requires the following:

- Dynamic linking against OpenSSL v3 library
- OpenSSL v3 FIPS module
- OpenSSL v3 FIPS configuration

#### Dynamically Linking Against the OpenSSL v3 Library

This is achieved by installing appropriate system OpenSSL v3 library and building `ziti-edge-tunnel` with dynamic links to it.

On Linux, you can use the following command to install OpenSSL:

```sh
sudo apt-get install libssl-dev
```

On MacOS, you can use the following command to install OpenSSL:

```sh
brew install openssl
```

Set CMake cache variable `VCPKG_OVERLAY_PORTS` to include the overlay that links against the installed OpenSSL v3 library ([../vcpkg-overlays/dynamic-libssl3]).

```sh
VCPKG_OVERLAY_PORTS="./vcpkg-overlays/dynamic-libssl3"
```

Next, build as normal and verify that the OpenSSL library is linked dynamically.

On Linux

```sh
ldd ziti-edge-tunnel
```

On MacOS

```sh
otool -L ziti-edge-tunnel
```

#### Acquiring OpenSSL FIPS Module

##### Install the OpenSSL FIPS Module

The OpenSSL FIPS module may be available via your package manager. You must ensure that the desired OpenSSL v3 library
is the first one that the `ziti-edge-tunnel` binary finds at runtime by, for example, ensuring no other OpenSSL v3
library is installed.

##### Build OpenSSL FIPS Module From Source

Follow these instructions if the module isn't available from your distribution's repositories.

Using vcpkg -- replace `<platform>` with `x64-linux` or `arm64-osx` depending on your target platform:

```sh
vcpkg install "openssl[fips]:<platform>-dynamic"
```

This builds OpenSSL FIPS module (`fips.so` or `fips.dylib`) and installs it into vcpkg directory 
under `packages/openssl_<platform>-dynamic/lib/ossl-modules`. 

Copy this module into standard OpenSSL module directory -- 
`/usr/lib/x86_64-linux-gnu/ossl-modules` on Linux or `/opt/homebrew/lib/ossl-modules` on MacOS.

## OpenSSL FIPS Configuration

Follow instructions in [OpenSSL FIPS User Guide](https://docs.openssl.org/master/man7/fips_module) 
to configure OpenSSL FIPS module.

## Running with FIPS Module

If everything is configured correctly, you should see the following in the log:

```
(9729)[        0.010]    INFO ziti-sdk:ziti.c:540 ziti_start_internal() ztx[0] enabling Ziti Context
(9729)[        0.010]    INFO ziti-sdk:ziti.c:557 ziti_start_internal() ztx[0] using tlsuv[v0.33.9.1/OpenSSL 3.3.1 4 Jun 2024 [FIPS]]
```
