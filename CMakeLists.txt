cmake_minimum_required(VERSION 3.12)
execute_process(
        COMMAND git describe --tags --dirty=-local
        OUTPUT_VARIABLE GIT_VERSION
        OUTPUT_STRIP_TRAILING_WHITESPACE
)
string(REGEX MATCH "([0-9]+\\.[0-9]+\\.[0-9]+)" ver "${GIT_VERSION}")

project(ziti-tunnel-sdk-c
        VERSION "${ver}"
        LANGUAGES C CXX)
include(CPack)
set(CPACK_PACKAGE_VENDOR "NetFoundry")

add_custom_target(bundle
        COMMENT "creates publishable artifacts")

file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/bundle)

macro(BUNDLE_COMP comp)
    add_custom_target(${comp}-bundle
            BYPRODUCTS ${CMAKE_BINARY_DIR}/bundle/${comp}-${CPACK_SYSTEM_NAME}_${CMAKE_SYSTEM_PROCESSOR}.zip
            DEPENDS ${comp}
            COMMAND zip ${CMAKE_BINARY_DIR}/bundle/${comp}-${CPACK_SYSTEM_NAME}_${CMAKE_SYSTEM_PROCESSOR}.zip ${comp}
            )
    add_dependencies(bundle ${comp}-bundle)
endmacro()

message("project version: ${PROJECT_VERSION} (git version ${GIT_VERSION})")
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

install(TARGETS lwipcore ziti-tunnel-sdk-c ziti-tunnel-cbs-c
        DESTINATION ${CMAKE_INSTALL_LIBDIR}
        )

if (WIN32)
install(TARGETS lwipwin32arch
        DESTINATION ${CMAKE_INSTALL_LIBDIR}
        )
endif()