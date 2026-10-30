# protobuf-c (runtime only)

This is a copy of `vcpkg-overlays/protobuf-c-runtime-only/protobuf-c` at the top of this repository. It builds the
protobuf-c runtime library without depending on protobuf and abseil. Recent abseil versions don't build with GCC 7 in
the `ziti-builder:v1` (Ubuntu bionic) image, and none of our builds need protobuf.

It's duplicated here because `entrypoint.sh` passes this directory as `VCPKG_OVERLAY_PORTS`, which replaces the value
set by the `vcpkg` preset in `CMakePresets.json`.

Don't edit this copy directly. See `vcpkg-overlays/protobuf-c-runtime-only/README.md` for why the overlay exists, how
it was created and how to update it for newer vcpkg baselines. Then copy the updated port here and check that the two
match:

```shell
diff -r -x README.md vcpkg-overlays/protobuf-c-runtime-only/protobuf-c \
    .github/actions/openziti-tunnel-build-action/gh-release/vcpkg-overlays/protobuf-c
```
