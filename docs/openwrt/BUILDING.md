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
$ ${ZITI_TUN_SRC_DIR}/script/openwrt-build.sh -s ${OPENWRT_DIR}
```

