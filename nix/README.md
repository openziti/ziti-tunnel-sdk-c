# Nix Support for ziti-edge-tunnel

## Prerequisites

- [Determinate Systems installer](https://zero-to-nix.com/start/install):

This enables flakes and the unified `nix` CLI out of the box. If you already
have Nix installed, make sure `experimental-features = nix-command flakes` is in
your `~/.config/nix/nix.conf`.

## Usage

### Build

```bash
nix build
```

The binary is at `./result/bin/ziti-edge-tunnel`.

### Run without installing

```bash
nix run . -- version
nix run . -- enroll --jwt /path/to/token.jwt --identity /path/to/identity.json
```

### NixOS module

Add the flake to your NixOS configuration inputs:

```nix
{
  inputs.ziti-tunnel.url = "github:openziti/ziti-tunnel-sdk-c";
}
```

Then enable the module:

```nix
{ inputs, ... }:
{
  imports = [ inputs.ziti-tunnel.nixosModules.default ];

  programs.ziti-edge-tunnel = {
    enable = true;
    service.enable = true;

    # Optional: enroll identities at boot
    enrollment.identities = {
      mynetwork = {
        jwtFile = "/path/to/enrollment.jwt";
        # identityFile defaults to /opt/openziti/etc/identities/mynetwork.json
      };
    };
  };
}
```

## Updating dependencies

When a new version of ziti-edge-tunnel is released, run the update script:

```bash
# Update to the latest release
./nix/update.sh

# Or pin to a specific version
./nix/update.sh v1.11.0
```

The script automatically:

1. Fetches the latest (or specified) tag from GitHub
2. Reads `ZITI_SDK_VERSION` and `tlsuv_VERSION` from the upstream CMake files
3. Pins the latest `subcommands.c` commit
4. Computes Nix source hashes for all dependencies
5. Updates `nix/packages/ziti-edge-tunnel.nix` in-place

Then verify the build:

```bash
nix build
./result/bin/ziti-edge-tunnel version
```

> **Note:** `lwip` and `lwip-contrib` are pinned to stable release branches and
> rarely change. If they do, update their `rev` and `hash` fields in
> `nix/packages/ziti-edge-tunnel.nix` manually.
