# Nix Support for ziti-edge-tunnel

## Prerequisites

- [Determinate Systems installer](https://zero-to-nix.com/start/install):

This enables flakes and the unified `nix` CLI out of the box. If you already
have Nix installed, make sure `experimental-features = [ "nix-command" "flakes" ];` is in
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

## Installing

Add the flake to your NixOS configuration inputs:

```nix
{
  inputs.ziti-edge-tunnel.url = "github:openziti/ziti-tunnel-sdk-c";
}
```

Then enable the module:

```nix
{ inputs, ... }:
{
  imports = [ inputs.ziti-tunnel.nixosModules.default ];

  services.ziti-edge-tunnel = {
    enable = true;

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

Installing will set up a systemd service for you.

## Updating dependencies

When a new version of ziti-edge-tunnel is released, update the dependencies:

```bash
# Update the flake.lock file
nix flake update

# Update to the latest release
./nix/update.sh

# Or pin to a specific version
./nix/update.sh v1.11.0
```

Then verify the build:

```bash
nix build
./result/bin/ziti-edge-tunnel version
```

> **Note:** `lwip` and `lwip-contrib` are pinned to stable release branches and
> rarely change. If they do, update their `rev` and `hash` fields in
> `nix/packages/ziti-edge-tunnel.nix` manually.
