cmake_minimum_required(VERSION 3.14)
if(NOT ZITI_SDK_C_BRANCH)
    #allow using a different branch of the CSDK easily
    set(ZITI_SDK_C_BRANCH "0.26.29")
endif()

# if TUNNEL_SDK_ONLY then don't descend into programs/ziti-edge-tunnel
option(TUNNEL_SDK_ONLY "build only ziti-tunnel-sdk (without ziti)" OFF)
message("tunnel only = ${TUNNEL_SDK_ONLY}")

find_package(Git)
if(NOT GIT_VERSION AND GIT_FOUND)
    message("Found Git executable \"${GIT_EXECUTABLE}\".")
    # Generate a git-describe version string from Git repository tags
    execute_process(
        COMMAND ${GIT_EXECUTABLE} describe --tags --dirty=-local --match "v*"
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        OUTPUT_VARIABLE GIT_VERSION
        RESULT_VARIABLE GIT_ERROR_CODE
        OUTPUT_STRIP_TRAILING_WHITESPACE
        )
    if(GIT_ERROR_CODE)
        message(SEND_ERROR "Error trying to get GIT_VERSION: \"${GIT_VERSION}\" and GIT_ERROR_CODE: \"${GIT_ERROR_CODE}\".")
    else()
        message(DEBUG "Found Git version \"${GIT_VERSION}\" without error code.")
    endif()
endif()

set(DUMMY_SEMVER "0.0.0")

# Final fallback: Unless building packages, just use a bogus version string
# that is semantically older than anything else and spit out a warning to the
# developer.
if(NOT GIT_VERSION)
    set(GIT_VERSION v0.0.0-unknown)
    set(PROJECT_SEMVER "${DUMMY_SEMVER}")
    message(WARNING "GIT_VERSION not set. Using dummy PROJECT_SEMVER: \"${PROJECT_SEMVER}\", GIT_VERSION: \"${GIT_VERSION}\".")
else()
    string(REGEX MATCH "([0-9]+\\.[0-9]+\\.[0-9]+)" PROJECT_SEMVER "${GIT_VERSION}")
    if(NOT PROJECT_SEMVER)
        set(PROJECT_SEMVER "${DUMMY_SEMVER}")
        message(WARNING "SEMVER could not be parsed from GIT_VERSION: ${GIT_VERSION}. Setting to PROJECT_SEMVER: ${PROJECT_SEMVER}")
    else()
        message("Parsed GIT_VERSION: \"${GIT_VERSION}\", PROJECT_SEMVER: \"${PROJECT_SEMVER}\".")
    endif()
endif()

option(DISABLE_SEMVER_VERIFICATION "Toggle SEMVER verification for BUILD_DIST_PACKAGES" OFF)
option(BUILD_DIST_PACKAGES "Build packages for distribution package managers" OFF)

# Require explicitely disabling SEMVER verification for bulding DIST packages.
if(NOT DISABLE_SEMVER_VERIFICATION AND BUILD_DIST_PACKAGES AND PROJECT_SEMVER VERSION_EQUAL "${DUMMY_SEMVER}")
    unset(GIT_VERSION CACHE)
    unset(GIT_ERROR_CODE CACHE)
    unset(PROJECT_SEMVER CACHE)
    unset(BUILD_DIST_PACKAGES CACHE)
    unset(DISABLE_SEMVER_VERIFICATION CACHE)
    message(FATAL_ERROR "SEMVER Verification failed. A valid SEMVER is required for correct package version composition. To override, set DISABLE_SEMVER_VERIFICATION=ON.")
endif()

project(ziti-tunnel-sdk-c
        VERSION "${PROJECT_SEMVER}"
        LANGUAGES C CXX)

if(NOT BUILD_DIST_PACKAGES)
    include(CPack)
    set(CPACK_PACKAGE_VENDOR "NetFoundry")
endif()

set(CMAKE_C_STANDARD 99)

if (MSVC)
    add_compile_options(-Zi)
else()
    add_compile_options(-g)
endif()

add_custom_target(bundle
        COMMENT "creates publishable artifacts")

file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/bundle)

macro(BUNDLE_COMP comp)
    add_custom_target(${comp}-bundle
        BYPRODUCTS ${CMAKE_BINARY_DIR}/bundle/${comp}-${CMAKE_SYSTEM_NAME}_${CMAKE_SYSTEM_PROCESSOR}.zip
        DEPENDS ${comp}
        COMMAND ${CMAKE_COMMAND} -E tar "cf" "${CMAKE_BINARY_DIR}/bundle/${comp}-${CMAKE_SYSTEM_NAME}_${CMAKE_SYSTEM_PROCESSOR}.zip" --format=7zip -- ${comp}${CMAKE_EXECUTABLE_SUFFIX} ${${comp}_BUNDLE_COMPS})
    add_dependencies(bundle ${comp}-bundle)
endmacro()

message("project version: ${PROJECT_VERSION} (git version ${GIT_VERSION})")
message("cross-compiling: ${CMAKE_CROSSCOMPILING}")

link_directories(${CMAKE_BINARY_DIR}/lib)

add_subdirectory(deps)

add_subdirectory(lib/ziti-tunnel)

if(NOT TUNNEL_SDK_ONLY)
add_subdirectory(lib/ziti-tunnel-cbs)
add_subdirectory(programs)
endif()

if (WIN32)
set(CMAKE_INSTALL_LIBDIR lib)
set(CMAKE_INSTALL_INCLUDEDIR include)
endif()

# lwip macro defaults. override on command line or in parent cmakelists.
set(LWIP_MEM_SIZE 1048576 CACHE STRING "LWIP MEM_SIZE option")
set(LWIP_PBUF_POOL_SIZE 1024 CACHE STRING "LWIP PBUF_POOL_SIZE option")
set(UDP_MAX_CONNECTIONS 512 CACHE STRING "LWIP MEMP_NUM_UDP_PCB option")
set(TCP_MAX_QUEUED_SEGMENTS 2048 CACHE STRING "LWIP MEMP_NUM_TCP_SEG option")
set(TCP_MAX_CONNECTIONS 512 CACHE STRING "LWIP MEMP_NUM_TCP_PCB option")

target_compile_definitions(lwipcore
    PUBLIC MEM_SIZE=${LWIP_MEM_SIZE}
    PUBLIC PBUF_POOL_SIZE=${LWIP_PBUF_POOL_SIZE}
    PUBLIC MEMP_NUM_TCP_PCB=${TCP_MAX_CONNECTIONS}
    PUBLIC MEMP_NUM_TCP_SEG=${TCP_MAX_QUEUED_SEGMENTS}
    PUBLIC MEMP_NUM_UDP_PCB=${UDP_MAX_CONNECTIONS}
)

if (WIN32)
install(TARGETS lwipwin32arch
        DESTINATION ${CMAKE_INSTALL_LIBDIR}
        )
endif()
