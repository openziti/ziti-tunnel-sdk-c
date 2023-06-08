Building `ziti-edge-tunnel` for OpenWRT
---------------------------------------

## OpenWRT SDK
1. Obtain [OpenWRT SDK](https://openwrt.org/docs/guide-developer/start)
   
   Some hardware manufactures provide their own pre-configured SDKs for download to simplify
   target configuration:
    * Teltonika [SDK](https://wiki.teltonika-networks.com/view/Software_Development_Kit)

2. follow instructions to build toolchain and target image for your target platform/device (it takes a while)

## Ziti Tunneler SDK and `ziti-edge-tunnel`
check out [ziti-tunneler-sdk-c](https://github.com/openziti/ziti-tunnel-sdk-c.git) or 
download [source code](https://github.com/openziti/ziti-tunnel-sdk-c/releases)

## Build `ziti-edge-tunnel`
Create your build directory. It could anywhere.
in the example below:
* `ZITI_TUN_SRC_DIR` is the location of `ziti-tunneler-sdk-c` source
* `OPENWRT_DIR` is the location of OpenWRT SDK

```shell
$ mkdir /tmp/my-ziti-build
$ cd /tmp/my-ziti-build
$ ${ZITI_TUN_SRC_DIR}/scripts/openwrt-build.sh -s ${OPENWRT_DIR}
```

## TELTONIKA notes

### RUTOS

Follow instructions [here](https://wiki.teltonika-networks.com/view/RUTOS_Software_Development_Kit_instructions), 
however it is missing one step. After installing requirements with `apt`, you'll need to get `nodejs` and `npm` as updated
OpenWRT toolchain requires it.

The easiest way to get the right version(>= 12.0) of `nodejs` is to use [NodeJS Version Manager](https://github.com/nvm-sh/nvm)

After `nvm` is installed:
```bash
$ nvm install 12
Downloading and installing node v12.22.12...
Downloading https://nodejs.org/dist/v12.22.12/node-v12.22.12-linux-x64.tar.xz...
############################################################################################################################################################################## 100.0%
Computing checksum with sha256sum
Checksums matched!
Now using node v12.22.12 (npm v6.14.16)
Creating default alias: default -> 12 (-> v12.22.12)
```

Once it is done, open a new shell so that `nodejs` is available and continue following instructions with `./scripts/feeds update -a` step.