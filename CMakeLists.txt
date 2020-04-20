cmake_minimum_required(VERSION 3.12)
file(READ version ver)

project(ziti-tunneler-sdk
        VERSION ${ver}
        LANGUAGES C CXX)
include(CPack)

message("project version: ${PROJECT_VERSION}")
message("cross-compiling: ${CMAKE_CROSSCOMPILING}")

link_directories(${CMAKE_BINARY_DIR}/lib)

add_subdirectory(deps)
add_subdirectory(lib)
add_subdirectory(programs)

if (WIN32)
set(CMAKE_INSTALL_LIBDIR lib)
set(CMAKE_INSTALL_INCLUDEDIR include)
endif()

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(TARGETS lwipcore lwipwin32arch ziti_tunneler
        DESTINATION ${CMAKE_INSTALL_LIBDIR}
        )