# Release v0.17.21

## What's new
* config.json and config.json.backup files will be created in the identity path. This file will have the configuration details like identifier name, endpoint name, Active status etc.

## Fixed
* Builds produce by CI may fail with SIGILL(Illegal instruction) on some machines (fixed in ziti-sdk v0.26.16).


# Release v0.17.20

## What's new

* Publish official `ziti-edge-tunnel` binaries for arm64(aarch64) architecture
* Increased `lwip` limits

## Fixes

* Fix: compilation issues when using MS Visual Studio compiler