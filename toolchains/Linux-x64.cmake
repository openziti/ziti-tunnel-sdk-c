set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

set(triple x86_64-linux-gnu)

find_program(_clang_c NAMES clang-17)
find_program(_clang_cxx NAMES clang++-17)
if(_clang_c AND _clang_cxx)
    set(CMAKE_C_COMPILER "${_clang_c}")
    set(CMAKE_CXX_COMPILER "${_clang_cxx}")
else()
    set(CMAKE_C_COMPILER gcc)
    set(CMAKE_CXX_COMPILER g++)
endif()

set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE amd64)
set(CPACK_RPM_PACKAGE_ARCHITECTURE x86_64)

set(ENV{PKG_CONFIG_PATH} /usr/lib/${triple}/pkgconfig)
