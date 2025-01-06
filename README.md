[![Apache 2.0](https://img.shields.io/github/license/openziti/ziti-tunnel-sdk-c)](https://github.com/openziti/ziti-tunnel-sdk-c/blob/master/LICENSE)
[![Latest Release](https://img.shields.io/github/v/release/openziti/ziti-tunnel-sdk-c)](https://github.com/openziti/ziti-tunnel-sdk-c/releases/latest)
[![Build Status](https://github.com/openziti/ziti-tunnel-sdk-c/workflows/CI%20build/badge.svg)](https://github.com/openziti/ziti-tunnel-sdk-c/actions?query=workflow%3A%22CI+build%22)

# Ziti Tunneler SDK

The Ziti Tunneler SDK provides protocol translation and other common functions
that are useful to Ziti Tunnelers.

## What's a Ziti Tunneler?

[The main article about tunnelers is here](https://openziti.io/docs/reference/tunnelers/linux/). Editors may follow the
"Edit this page" link on every page.

## What is the Ziti Tunneler SDK?

The Ziti Tunneler SDK provides functionality that is common to Ziti Tunnelers across
supported operating systems:

- Converse with TCP/IP peers
- Map TCP/IP connections to Ziti sessions
- Respond to DNS queries for Ziti service hostnames

A Ziti Tunneler application that uses the Ziti Tunneler SDK only needs to
implement platform-specific functionality, such as creating a virtual network
interface, and providing a user interface.

A set of callback
functions that interact with the specific _ziti-sdk_ that the application
uses (e.g. `ziti-sdk-c`, `ziti-sdk-go`).

The Ziti Tunneler SDK includes an implementation of the required callback
functions for `ziti-sdk-c`. Here's how a minimal tunneler application written
in C could use the Ziti Tunneler SDK:

```c
int main(int argc, char *argv[]) {
    uv_loop_t *nf_loop = uv_default_loop();
    netif_driver tun = tun_open(NULL, 0); /* open a tun device, and */

    if (tun == NULL) {
        fprintf(stderr, "failed to open network interface: %s\n", tun_error);
        return 1;
    }

    tunneler_sdk_options tunneler_opts = {
            .netif_driver = tun,
            .ziti_dial = ziti_sdk_c_dial,
            .ziti_close = ziti_sdk_c_close,
            .ziti_write = ziti_sdk_c_write
    };
    tunneler_context TUNNEL_CTX = NF_tunneler_init(&tunneler_opts, nf_loop);

    nf_options opts = {
            .init_cb = on_nf_init,
            .config = argv[1],
            .service_cb = on_service,
            .ctx = TUNNEL_CTX, /* this is passed to the service_cb */
            .refresh_interval = 10,
            .config_types = cfg_types,
    };

    if (NF_init_opts(&opts, nf_loop, NULL) != 0) {
        fprintf(stderr, "failed to initialize ziti\n");
        return 1;
    }

    if (uv_run(nf_loop, UV_RUN_DEFAULT) != 0) {
        fprintf(stderr, "failed to run event loop\n");
        exit(1);
    }

    free(TUNNEL_CTX);
    return 0;
}
```

Once the Ziti Tunneler SDK is initialized with a network device and ziti-sdk
callbacks, a tunneler application only needs to indicate which service(s)
that should be  

## Run with Docker

Refer to [the Docker README](./docker/README.md) for instructions to run `ziti-edge-tunnel` with Docker.

## Multi-Platform Linux Crossbuild Container

Refer to [the BUILD article](./BUILD.md) for instructions to build `ziti-edge-tunnel`, including the crossbuild container image.
