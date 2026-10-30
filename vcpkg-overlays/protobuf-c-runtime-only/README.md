# protobuf-c (runtime only)

This overlay builds only the protobuf-c runtime library (`libprotobuf-c`), without depending on protobuf.

## Why it's here

The upstream vcpkg `protobuf-c` port always depends on `protobuf`, which depends on `abseil`. But protobuf is only
needed to build the `protoc-gen-c` code generator (the port's `tools` feature). The runtime library is plain C and
doesn't link protobuf or abseil (except for static MSVC builds, which we don't use).

We don't need `protoc-gen-c`: ziti-sdk-c checks in its generated `*.pb-c.c` sources and only finds `libprotobuf-c`
via pkg-config. So without this overlay every build compiles abseil and protobuf, for both the host and the target
triplets, and throws them away. That is slow, and recent abseil versions don't build with older compilers, such as
GCC 7 in the `ziti-builder:v1` (Ubuntu bionic) image used for release builds.

With this overlay, `protobuf-c` pulls in only `vcpkg-cmake` and `vcpkg-cmake-config`. `protobuf-c[tools]` still
depends on protobuf, so code generation remains possible if it's ever needed.

The overlay is enabled for all builds by the `vcpkg` preset in `CMakePresets.json`. Builds under
`.github/actions/openziti-tunnel-build-action` set their own `VCPKG_OVERLAY_PORTS`, which replaces the preset's
value, so builders that need this overlay keep a copy in their own `vcpkg-overlays` directory
(currently `gh-release/vcpkg-overlays/protobuf-c`). Keep those copies identical to this one.

## How it was created

Starting from the upstream port in microsoft/vcpkg (`ports/protobuf-c`, protobuf-c 1.5.2 at baseline
`a2f9862da6d88040a8537fb9b8cb24deaa9a196b`):

- `vcpkg.json`: moved `protobuf` from the top-level `dependencies` into the `tools` feature's dependencies.
- `portfile.cmake`: unchanged, except it applies `runtime-only.patch` instead of upstream's
  `fix-dependency-protobuf.patch`.
- `fix-crt-linkage.patch`: copied unchanged from upstream.
- `runtime-only.patch`: replaces `fix-dependency-protobuf.patch`. It moves `option(BUILD_PROTOC ...)` above the
  dependency lookups in `build-cmake/CMakeLists.txt`, and wraps `find_package(Protobuf ...)`, `find_package(absl ...)`
  and the abseil/utf8_range link setup in `if(BUILD_PROTOC)`. Inside that block `find_package(Protobuf CONFIG)` is
  `REQUIRED`, which is what upstream's patch did. The portfile maps the `tools` feature to `BUILD_PROTOC`, so it's
  `OFF` unless `tools` is requested.

## Updating for a newer vcpkg baseline

When `builtin-baseline` in `vcpkg.json` changes, check whether upstream's `ports/protobuf-c` changed:

```shell
git -C "$VCPKG_ROOT" diff <old-baseline> <new-baseline> -- ports/protobuf-c
```

If nothing changed, there's nothing to do. Otherwise:

1. Copy the new upstream `portfile.cmake`, `vcpkg.json` and patches over this port, then reapply the changes listed
   above. `vcpkg.json` needs `protobuf` moved under `tools`, and `portfile.cmake` needs `runtime-only.patch` in place
   of `fix-dependency-protobuf.patch`. Upstream may have changed or dropped `fix-dependency-protobuf.patch`; check
   whether `runtime-only.patch` still makes it unnecessary.
2. If the protobuf-c version changed, regenerate `runtime-only.patch` against the new source. Apply upstream's other
   patches first (currently `fix-crt-linkage.patch`), because vcpkg applies the patches in the order they're listed:

   ```shell
   curl -sL https://github.com/protobuf-c/protobuf-c/archive/refs/tags/v<version>.tar.gz | tar xz
   cd protobuf-c-<version>
   git init -q && git add -A && git commit -qm base
   git apply /path/to/fix-crt-linkage.patch && git commit -qam crt
   # edit build-cmake/CMakeLists.txt as described above
   git diff > /path/to/runtime-only.patch
   ```

3. Check that protobuf and abseil are no longer in the install plan, and that the port installs:

   ```shell
   vcpkg install protobuf-c --dry-run --classic --overlay-ports=./vcpkg-overlays/protobuf-c-runtime-only
   vcpkg install protobuf-c --classic --overlay-ports=./vcpkg-overlays/protobuf-c-runtime-only
   ```

   The dry run should list only `protobuf-c`, `vcpkg-cmake` and `vcpkg-cmake-config`. The install should produce
   `lib/libprotobuf-c.a` and `lib/pkgconfig/libprotobuf-c.pc`.

4. Copy the updated port to each builder that carries a copy (`gh-release/vcpkg-overlays/protobuf-c`), and confirm
   they match:

   ```shell
   diff -r -x README.md vcpkg-overlays/protobuf-c-runtime-only/protobuf-c \
       .github/actions/openziti-tunnel-build-action/gh-release/vcpkg-overlays/protobuf-c
   ```

If upstream vcpkg makes `protobuf` a dependency of the `tools` feature only, this overlay and its copies can be
deleted.
