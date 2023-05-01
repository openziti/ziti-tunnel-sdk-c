set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

set(triple aarch64-linux-gnu)

set(CMAKE_C_COMPILER ${triple}-gcc)
set(CMAKE_CXX_COMPILER ${triple}-g++)

set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE arm64)
set(CPACK_RPM_PACKAGE_ARCHITECTURE aarch64)

set(ENV{PKG_CONFIG_PATH} /usr/lib/${triple}/pkgconfig)