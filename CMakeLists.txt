cmake_minimum_required(VERSION 3.12)
file(READ version ver)

project(ziti-tunneler-sdk
        VERSION ${ver}
        LANGUAGES C CXX)

message("project version: ${PROJECT_VERSION}")

if (WIN32)
    message("WIN32 build. Creating: ${CMAKE_BINARY_DIR}/cmake_install")
    file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/cmake_install)
    message("WIN32 build. Creating: ${CMAKE_BINARY_DIR}/cmake_install/ziti-sdk-${PROJECT_VERSION}")
    file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/cmake_install/ziti-sdk-${PROJECT_VERSION})
    set(CMAKE_INSTALL_PREFIX ${CMAKE_BINARY_DIR}/cmake_install/ziti-sdk-${PROJECT_VERSION})
else()
    set(CMAKE_INSTALL_PREFIX /opt/netfoundry/${PROJECT_NAME}-${PROJECT_VERSION})
endif()

message("cross-compiling ${CMAKE_CROSSCOMPILING}")

# Get the current working branch
execute_process(
        COMMAND git rev-parse --abbrev-ref HEAD
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_BRANCH
        OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Get the latest abbreviated commit hash of the working branch
execute_process(
        COMMAND git log -1 --format=%h
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_COMMIT_HASH
        OUTPUT_STRIP_TRAILING_WHITESPACE
)

# capture build date
execute_process(
        COMMAND date +%a-%m/%d/%Y-%H:%M:%S-%Z
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE BUILD_DATE
        OUTPUT_STRIP_TRAILING_WHITESPACE
)

message("git info:")
message("   branch : ${GIT_BRANCH}")
message("     hash : ${GIT_COMMIT_HASH}")
message("     date : ${BUILD_DATE}")

if(DEFINED ENV{BITBUCKET_BUILD_NUMBER})
    set(ZITI_BUILDNUM $ENV{BITBUCKET_BUILD_NUMBER})
else()
    set(ZITI_BUILDNUM local)
endif()

set(ZITI_VERSION ${PROJECT_VERSION}-${ZITI_BUILDNUM})

link_directories(${CMAKE_BINARY_DIR}/lib)

add_subdirectory(deps)

if(WIN32)
    add_subdirectory(windows)
endif()
