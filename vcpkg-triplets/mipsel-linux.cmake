set(VCPKG_TARGET_ARCHITECTURE mipsel)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE static)
set(VCPKG_CMAKE_SYSTEM_NAME Linux)
# ci-linux-mipsel currently chainloads Linux-arm.cmake; preserved here until a correct mipsel toolchain is added
set(VCPKG_CHAINLOAD_TOOLCHAIN_FILE "${CMAKE_CURRENT_LIST_DIR}/../toolchains/Linux-arm.cmake")
