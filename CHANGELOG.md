# Release v0.17.23

## What's new

* Tunneler SDK: Recursive DNS support -- DNS queries not matched by Ziti services are forwarded to upstream server (if configured)
* `ziti-edge-tunnel`
  * add `-u|--dns-upstream` option for setting DNS upstream server
  * `-n/--dns` option is removed

# Release v0.17.21

## What's new

* add script and document building of `ziti-edge-tunnel` with OpenWRT (see [instructions](docs/openwrt/BUILDING.md))


# Release v0.17.20

## What's new

* Publish official `ziti-edge-tunnel` binaries for arm64(aarch64) architecture
* Increased `lwip` limits

## Fixes

* Fix: compilation issues when using MS Visual Studio compiler