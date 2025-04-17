Using ziti-edge-tunnel in FIPS mode.
========================================================

This document describes how to build and run ziti-edge-tunnel in FIPS mode.

Using FIPS mode requires the following:
- dynamic linking against OpenSSL library
- OpenSSL FIPS module
- OpenSSL FIPS configuration

## Dynamically linking against OpenSSL library

This is achieved by installing appropriate system OpenSSL library 
and building ziti-edge-tunnel linked to it.

This is default for ziti-edge-tunnel distributed via Linux package manager (DEB/RPM)s.

On Linux, you can use the following command to install OpenSSL:
```sh
sudo apt-get install libssl-dev
```
On MacOS, you can use the following command to install OpenSSL:
```sh
brew install openssl
```
Next use vcpkg overlay to link against installed OpenSSL library.
An example of vcpkg overlay can be found in the [../vcpkg-overlays/full-distro/fedora-40/openssl]

Next, build as normal and verify that the OpenSSL library is linked dynamically.

On Linux
```sh
ldd ziti-edge-tunnel
```

On MacOS
```sh
otool -L ziti-edge-tunnel
```

## Acquiring OpenSSL FIPS module

OpenSSL FIPS module may be available via your package manager. Check your distro.

If that is not the case, you can build it from source.

Using vcpkg -- replace `<platform>` with `x64-linux` or `arm64-osx` depending on your target platform:
```sh
vcpkg install "openssl[fips]:<platform>-dynamic"
```

This builds OpenSSL FIPS module (`fips.so` or `fips.dylib`) and installs it into vcpkg directory 
under `packages/openssl_<platform>-dynamic/lib/ossl-modules`. 

Copy this module into standard OpenSSL module directory -- 
`/usr/lib/x86_64-linux-gnu/ossl-modules` on Linux or `/opt/homebrew/lib/ossl-modules` on MacOS.

## OpenSSL FIPS configuration
Follow instructions in [OpenSSL FIPS User Guide](https://docs.openssl.org/master/man7/fips_module) 
to configure OpenSSL FIPS module.
