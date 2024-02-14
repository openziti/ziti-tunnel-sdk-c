# Building the Project

The following steps should get your C SDK for Ziti building. C development is specific to your operating system and 
tool chain used. These steps should work properly for you but if your OS has variations you may need to adapt these steps accordingly.

## Prerequisites

This repository expects the user to have at least a basic understanding of what a Ziti Network
is. To use this library it is also required to have a functioning Ziti Network available to use.
To learn more about what Ziti is or how to learn how to setup a Ziti Network head over to [the official documentation
site](https://openziti.io/).

### Building Requirements

* [cmake](https://cmake.org/install/)
* make sure cmake is on your path or replace the following `cmake` commands with the fully qualified path to the binary
* [vcpkg](https://github.com/microsoft/vcpkg) is now used for dependencies.

### Setting up vcpkg

To setup vcpkg you'll need to clone the actual vcpkg repository. The first step will have you set this environment variable.
It should be set to somewhere durable, such as wherever you check your projects into. The example commands below use $HOME/%USERPROFILE%
but you should probably change this to your liking.

#### Linux or macOS

* set/export an environment variable named `VCPKG_ROOT`. for example (use an appropriate location): `export VCPKG_ROOT=${HOME}/vcpkg`
* create the directory: `mkdir -p ${VCPKG_ROOT}`
* clone the vcpkg project: `git clone git@github.com:microsoft/vcpkg.git ${VCPKG_ROOT}`
* run the bootstrap-vcpkg for your platform: `${VCPKG_ROOT}/bootstrap-vcpkg.sh`

#### Windows

* set/export an environment variable named `VCPKG_ROOT`. for example (use an appropriate location): `SET VCPKG_ROOT=%USERPROFILE%\vcpkg`
* create the directory: `mkdir %VCPKG_ROOT%`
* clone the vcpkg project: `git clone git@github.com:microsoft/vcpkg.git %VCPKG_ROOT%`
* run the bootstrap-vcpkg for your platform: `%VCPKG_ROOT%/bootstrap-vcpkg.bat`

## Building

Make sure you have set up vcpkg (see above). Building the SDK is accomplished with the following commands from the
checkout root. Replace the `--preset` value with the one that matches your needs or create your own preset. You
can run `cmake` from the checkout root with an `unknown` param passed to `--preset` to see the list of presets:
`cmake --preset unknown ${ZITI_TUNNELER_SDK_C_ROOT}/.`

Build the SDK with:

```bash
mkdir build
cd build
cmake --preset ci-linux-x64 ..
cmake --build .
```

## VCPKG

### Presets

This project makes use of [presets][1] to simplify the process of configuring
the project. As a developer, you are recommended to always have the [latest
CMake version][2] installed to make use of the latest Quality-of-Life
additions.

As a developer, you should create a `CMakeUserPresets.json` file at the root of
the project:

```json
{
  "version": 2,
  "cmakeMinimumRequired": {
    "major": 3,
    "minor": 14,
    "patch": 0
  },
  "configurePresets": [
    {
      "name": "dev",
      "binaryDir": "${sourceDir}/build/dev",
      "$comment": "replace <os> below with your development target, e.g. linux-x64 or windows-arm64",
      "inherits": ["dev-mode", "vcpkg", "ci-<os>"],
      "cacheVariables": {
        "CMAKE_BUILD_TYPE": "Debug"
      }
    }
  ],
  "buildPresets": [
    {
      "name": "dev",
      "configurePreset": "dev",
      "configuration": "Debug"
    }
  ],
  "testPresets": [
    {
      "name": "dev",
      "configurePreset": "dev",
      "configuration": "Debug",
      "output": {
        "outputOnFailure": true
      }
    }
  ]
}
```

You should replace `<os>` in your newly created presets file with the name of
the operating system you have, which may be `win64` or `unix`. You can see what
these correspond to in the [`CMakePresets.json`](CMakePresets.json) file.

`CMakeUserPresets.json` is also the perfect place in which you can put all
sorts of things that you would otherwise want to pass to the configure command
in the terminal.

### Dependency manager

The above preset will make use of the [vcpkg][vcpkg] dependency manager. After
installing it, make sure the `VCPKG_ROOT` environment variable is pointing at
the directory where the vcpkg executable is. On Windows, you might also want
to inherit from the `vcpkg-win64-static` preset, which will make vcpkg install
the dependencies as static libraries. This is only necessary if you don't want
to setup `PATH` to run tests.

[vcpkg]: https://github.com/microsoft/vcpkg

### Configure, build and test

If you followed the above instructions, then you can configure, build and test
the project respectively with the following commands from the project root on
any operating system with any build system:

```sh
cmake --preset=dev
cmake --build --preset=dev
ctest --preset=dev
```

If you are using a compatible editor (e.g. VSCode) or IDE (e.g. CLion, VS), you
will also be able to select the above created user presets for automatic
integration.

Please note that both the build and test commands accept a `-j` flag to specify
the number of jobs to use, which should ideally be specified to the number of
threads your CPU has. You may also want to add that to your preset using the
`jobs` property, see the [presets documentation][1] for more details.

## Cross-compile with Docker

The default build architecture is x86_64. You can also cross-compile the distribution-specific Linux package or the
generic binary with Docker. Both approaches use an x86 (x86_64, amd64) container image to build the artifacts for arm64
and arm architectures.

### Build the Linux Package with Docker

The Debian and RedHat packages are built in GitHub and uploaded to DEB and RPM repositories. The Debian package may be
cross-compiled for arm64 or arm with [a few exceptions](.github/cpack-matrix.yml). Cross-compiling the RPM is not yet
supported.

1. build the x64 package builder image
1. run the x64 builder image to build the package for the target architecture

The `ziti-edge-tunnel` binary is also built for the target architecture and included in the package with appropriate
parameters for the target distribution.

#### Build the Package Builder Image

Build the x64 package builder image for Ubuntu Bionic 18.04. There are builder images for several Ubuntu and RedHat
vintages that will work with a wide variety of Debian and RPM family distros.

```bash
cd ./.github/actions/openziti-tunnel-build-action/ubuntu-22.04/
docker buildx build --platform linux/amd64 --tag jammy-builder . --load
```

#### Run the Package Builder Container

Cross-build the Debian package for arm64 in the x64 builder container. The `ci-linux-arm64` in this example is an
architecture-specific CMake [preset][1], and the optional TLS library variable overrides the default library, MBed-TLS.

```bash
docker run \
  --rm \
  --volume "${PWD}:/github/workspace" \
  --workdir "/github/workspace" \
  --env "TLSUV_TLSLIB=openssl" \
  jammy-builder \
    ci-linux-arm64
```

### Build the Binary with Docker

All of the Ziti projects that leverage Ziti's C-SDK are built with a shared builder image: `openziti/ziti-builder`. This
project provides a wrapper script for cross-building the generic `ziti-edge-tunnel` binary using this builder image
optimized for compatibility, i.e., libc 2.27 and static Mbed-TLS library.

Without any arguments, the `ziti-builder.sh` script will build the `bundle` target with the `ci-linux-x64` (amd64)
preset, placing the resulting ZIP archive in `./build/bundle/`, and the bare executable in
`./build/programs/ziti-edge-tunnel/Release/`.

Build the generic binary for arm64 with the `ci-linux-arm64` preset.

```bash
./scripts/ziti-builder.sh -p ci-linux-arm64
```

To build with OpenSSL on this Ubuntu Bionic-based (glibc 2.27) builder image, `export TLSUV_TLSLIB=openssl` and change
`vcpkg.json` to statically compile "openssl" instead of "mbedtls."

[1]: https://cmake.org/cmake/help/latest/manual/cmake-presets.7.html
[2]: https://cmake.org/download/
