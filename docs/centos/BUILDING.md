# CentOS 7:

CentOS 7 ships with older versions of glibc, cmake and gcc that make it difficult to compile this project and its dependencies. Building on CentOS involves providing newer packages built by the upstream projects, or through an available Software Collection Library(SCL).

## Example: Building the `ziti-edge-tunnel` binary:


```bash
#We'll install CMake to this prefix, and let's make sure it's in the PATH
export CMAKE_PREFIX_INSTALL="/opt/cmake"

export PATH="${CMAKE_PREFIX_INSTALL}:${PATH}"

# Install project CMake required version
curl -L https://cmake.org/files/v3.22/cmake-3.22.3-linux-x86_64.sh -o ./cmake.sh

chmod +x cmake.sh

mkdir -p "${CMAKE_PREFIX_INSTALL}"
./cmake.sh --skip-license --prefix="${CMAKE_PREFIX_INSTALL}"
rm cmake.sh

# Install dependencies and SCL repository
yum install -y "@Development Tools" python3 zlib-devel centos-release-scl

# If doc generation desired, install doxygen
yum install -y graphviz doxygen

# Install suitable versions of GCC and Headers
yum install -y devtoolset-11 devtoolset-11-libatomic-devel

# Perform shallow clone with desired ziti-edge-tunnel version
git clone https://github.com/openziti/ziti-tunnel-sdk-c.git --branch v0.17.24 --depth 1

cd ziti-tunnel-sdk-c

# Activate SCL collection and build
scl enable devtoolset-11 bash

cmake -E make_directory ./build

cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=./toolchains/default.cmake -S . -B ./build

cmake --build ./build --target ziti-edge-tunnel --verbose

# Test the built program
./build/programs/ziti-edge-tunnel/ziti-edge-tunnel version
```