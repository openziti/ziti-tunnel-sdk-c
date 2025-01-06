set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

set(triple arm-linux-gnueabihf)

set(CMAKE_C_COMPILER ${triple}-gcc)
set(CMAKE_CXX_COMPILER ${triple}-g++)

set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE armhf)
set(CPACK_RPM_PACKAGE_ARCHITECTURE armv7hl)

set(ENV{PKG_CONFIG_PATH} /usr/lib/${triple}/pkgconfig)