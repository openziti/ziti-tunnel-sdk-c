set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

set(triple arm-linux-gnueabihf)

set(CMAKE_C_COMPILER ${triple}-gcc)
set(CMAKE_CXX_COMPILER ${triple}-g++)

set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE arm)
set(CPACK_RPM_PACKAGE_ARCHITECTURE armv7l)

set(ENV{PKG_CONFIG_PATH} /usr/lib/${triple}/pkgconfig)