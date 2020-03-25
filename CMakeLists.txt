cmake_minimum_required(VERSION 3.12)
file(READ version ver)

project(ziti-tunneler-sdk
        VERSION ${ver}
        LANGUAGES C CXX)

message("project version: ${PROJECT_VERSION}")
message("cross-compiling: ${CMAKE_CROSSCOMPILING}")

link_directories(${CMAKE_BINARY_DIR}/lib)

add_subdirectory(deps)
add_subdirectory(lib)
add_subdirectory(programs)
