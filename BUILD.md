# Building the Project

The following steps should get your C SDK for Ziti building. C development is specific to your operating system and 
tool chain used. These steps should work properly for you but if your OS has variations you may need to adapt these steps accordingly.

## Prerequisites

This repository expects the user to have at least a basic understanding of what a Ziti Network
is. To use this library it is also required to have a functioning Ziti Network availalbe to use.
To learn more about what Ziti is or how to learn how to setup a Ziti Network head over to [the official documentation
site](https://openziti.github.io/ziti/overview.html).

### Building Requirements

* [cmake](https://cmake.org/install/)
* make sure cmake is on your path or replace the following `cmake` commands with the fully qualified path to the binary
* [vcpkg](https://github.com/microsoft/vcpkg) is now used for dependencies.

### Setting up vcpkg

To setup vcpkg you'll need to clone the actual vcpkg repository. The first step will have you set this environment variable.
It should be set to somewhere durable, such as wherever you check your projects into. The example commands below use $HOME/%USERPROFILE%
but you should probably change this to your liking.

Linux/MacOS:

* set/export an environment variable named `VCPKG_ROOT`. for example (use an appropriate location): `export VCPKG_ROOT=${HOME}/vcpkg`
* create the directory: `mkdir -p ${VCPKG_ROOT}`
* clone the vcpkg project: `git clone git@github.com:microsoft/vcpkg.git ${VCPKG_ROOT}`
* run the bootstrap-vcpkg for your platform: `${VCPKG_ROOT}/bootstrap-vcpkg.sh`

Windows: 
* set/export an environment variable named `VCPKG_ROOT`. for example (use an appropriate location): `SET VCPKG_ROOT=%USERPROFILE%\vcpkg`
* create the directory: `mkdir %VCPKG_ROOT%`
* clone the vcpkg project: `git clone git@github.com:microsoft/vcpkg.git %VCPKG_ROOT%`
* run the bootstrap-vcpkg for your platform: `%VCPKG_ROOT%/bootstrap-vcpkg.bat`

## Building

Make sure you have setup vcpkg (see above). Building the SDK is accomplished with the following commands from the 
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

[1]: https://cmake.org/cmake/help/latest/manual/cmake-presets.7.html
[2]: https://cmake.org/download/

## Docker Crossbuilder Image

The CI job which also runs the included `ziti-builder.sh` builds this project inside a Docker container. The script will run the necessary container image if needed. The container image has the tools to cross-compile for target architectures arm, arm64. This script works for Linux, macOS, and WSL2 on Windows. Arm architecture hosts will experience slower build times due to emulation of this x86_64 container image.

Without any arguments, the `ziti-builder.sh` script will build the `bundle` target with the `ci-linux-x64` (amd64) preset, placing the resulting ZIP archive in `./build/bundle`.

```bash
./ziti-builder.sh
```

To build for a specific target architecture, use the `-p` argument to specify the vcpkg preset.

```bash
./ziti-builder.sh -p ci-linux-arm64
```

```bash
./cmake help
```
