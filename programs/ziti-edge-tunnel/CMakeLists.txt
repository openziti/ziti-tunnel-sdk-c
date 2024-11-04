project(ziti-edge-tunnel)

include(CheckFunctionExists)

if(CMAKE_SYSTEM_NAME STREQUAL Darwin)
    set(NETIF_DRIVER_SOURCE netif_driver/darwin/utun.c)
endif()
if(CMAKE_SYSTEM_NAME STREQUAL Linux)
    set(NETIF_DRIVER_SOURCE netif_driver/linux/tun.c netif_driver/linux/resolvers.c netif_driver/linux/utils.c netif_driver/linux/libiproute.c netif_driver/linux/capability.c)
    check_function_exists(capget ZITI_TUNNELER_SDK_HAVE_CAPGET)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL Windows)
    include(wintun.cmake)
    set(tun_lib wintun)
    set(wintun_dll "${wintun_SOURCE_DIR}/bin/${CMAKE_SYSTEM_PROCESSOR}/wintun.dll")
    set(NETIF_DRIVER_SOURCE netif_driver/windows/tun.c netif_driver/windows/tun.h)
endif()

if (MSVC)
    find_package(unofficial-getopt-win32 REQUIRED)
    set(getopt unofficial::getopt-win32::getopt)
endif ()

set(ZITI_INSTANCE_COMMON
        include/model/events.h
        include/model/dtos.h
        instance.c
        include/identity-utils.h
        config-utils.c
        include/config-utils.h
        instance-config.c
        include/instance-config.h
)
if (WIN32)
    set(ZITI_INSTANCE_OS
            windows-service.c
            include/windows/windows-service.h
            include/windows/windows-scripts.h
            windows-scripts.c
            windows/log_utils.c
            include/service-utils.h)
endif ()

add_executable(ziti-edge-tunnel ziti-edge-tunnel.c ${NETIF_DRIVER_SOURCE} ${ZITI_INSTANCE_COMMON} ${ZITI_INSTANCE_OS})
set_property(TARGET ziti-edge-tunnel PROPERTY C_STANDARD 11)

if(CMAKE_SYSTEM_NAME STREQUAL Windows)
    # copy wintun.dll to the directory that contains ziti-edge-tunnel.exe
    add_custom_command(
            TARGET ziti-edge-tunnel POST_BUILD
            COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${wintun_dll}" "$<TARGET_FILE_DIR:ziti-edge-tunnel>"
            COMMENT "Copying ${wintun_dll} to $<TARGET_FILE_DIR:ziti-edge-tunnel>"
    )
    # bundle components are relative to the target's build directory. no directory is needed here since we copied the dll to the build directory.
    set(ziti-edge-tunnel_BUNDLE_COMPS wintun.dll)
endif()

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
