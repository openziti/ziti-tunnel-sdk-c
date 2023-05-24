project(ziti-edge-tunnel)

if(CMAKE_SYSTEM_NAME STREQUAL Darwin)
    set(NETIF_DRIVER_SOURCE netif_driver/darwin/utun.c)
endif()
if(CMAKE_SYSTEM_NAME STREQUAL Linux)
    set(NETIF_DRIVER_SOURCE netif_driver/linux/tun.c netif_driver/linux/resolvers.c netif_driver/linux/utils.c)
    set(ZITI_INSTANCE_OS linux/libsystemd.c)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL Windows)
    include(wintun.cmake)
    set(tun_lib wintun)
    configure_file(${wintun_SOURCE_DIR}/bin/${CMAKE_SYSTEM_PROCESSOR}/wintun.dll ${CMAKE_CURRENT_BINARY_DIR}/wintun.dll COPYONLY)
    set(ziti-edge-tunnel_BUNDLE_COMPS ${CMAKE_CURRENT_BINARY_DIR}/wintun.dll)
    set(NETIF_DRIVER_SOURCE netif_driver/windows/tun.c netif_driver/windows/tun.h)
endif()

if (MSVC)
    message("using visual studio")
    FetchContent_Declare(win-c
            GIT_REPOSITORY https://github.com/netfoundry/win-c.git
            GIT_TAG master
            )
    FetchContent_MakeAvailable(win-c)
    set(getopt libwinc)
endif()

set(ZITI_INSTANCE_COMMON include/model/events.h include/model/dtos.h instance.c include/identity-utils.h config-utils.c include/config-utils.h instance-config.c include/instance-config.h)
if (WIN32)
    set(ZITI_INSTANCE_OS windows-service.c include/windows/windows-service.h include/windows/windows-scripts.h windows-scripts.c windows/log_utils.c include/service-utils.h)
endif ()

add_executable(ziti-edge-tunnel ziti-edge-tunnel.c ${NETIF_DRIVER_SOURCE} ${ZITI_INSTANCE_COMMON} ${ZITI_INSTANCE_OS})
set_property(TARGET ziti-edge-tunnel PROPERTY C_STANDARD 11)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    option(DISABLE_LIBSYSTEMD_FEATURE "libsystemd library integration toggle" OFF)
    message("DISABLE_LIBSYSTEMD_FEATURE: ${DISABLE_LIBSYSTEMD_FEATURE}")

    if (DISABLE_LIBSYSTEMD_FEATURE)
        target_compile_definitions(ziti-edge-tunnel PRIVATE EXCLUDE_LIBSYSTEMD_RESOLVER)
    else()
        find_package(PkgConfig REQUIRED)
        pkg_check_modules(LIBSYSTEMD IMPORTED_TARGET "libsystemd")

        if(LIBSYSTEMD_FOUND)
            if(LIBSYSTEMD_VERSION VERSION_LESS "229")
                message(FATAL_ERROR "Unsupported version of libsystemd detected. To disable libsystmd feature, set DISABLE_LIBSYSTEMD_FEATURE=ON.")
            endif()
        else()
            message(FATAL_ERROR "libsystemd not found. To disable libsytemd feature, set DISABLE_LIBSYSTEMD_FEATURE=ON")
        endif()
    endif()
endif()

target_include_directories(ziti-edge-tunnel
        PRIVATE include
        )

target_compile_definitions(ziti-edge-tunnel
        PRIVATE GIT_VERSION=${GIT_VERSION}
        PRIVATE ZITI_LOG_PREFIX=${PROJECT_NAME}
        PRIVATE ZITI_LOG_MODULE="ziti-edge-tunnel"
        )

target_link_libraries(ziti-edge-tunnel
        PUBLIC ziti ziti-tunnel-sdk-c ziti-tunnel-cbs-c
        PUBLIC ${tun_lib}
        PUBLIC subcommand ${getopt}
        )

BUNDLE_COMP(ziti-edge-tunnel)

install(TARGETS ziti-edge-tunnel
        DESTINATION ${CMAKE_INSTALL_BINDIR}
        COMPONENT ${PROJECT_NAME}
        )

if(CMAKE_SYSTEM_NAME STREQUAL Linux AND BUILD_DIST_PACKAGES)
        include("${CMAKE_CURRENT_SOURCE_DIR}/package/CPackPackage.cmake")
        include(CPack)
        unset(BUILD_DIST_PACKAGES CACHE)
endif()
