project(ziti-edge-tunnel)

if(CMAKE_SYSTEM_NAME STREQUAL Darwin)
    set(NETIF_DRIVER_SOURCE netif_driver/darwin/utun.c)
endif()
if(CMAKE_SYSTEM_NAME STREQUAL Linux)
    set(NETIF_DRIVER_SOURCE netif_driver/linux/tun.c)
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

set(ZITI_INSTANCE include/model/events.h include/model/dtos.h instance.c include/instance.h)

add_executable(ziti-edge-tunnel ziti-edge-tunnel.c ${NETIF_DRIVER_SOURCE} dnsmasq_manager.c ${ZITI_INSTANCE})
set_property(TARGET ziti-edge-tunnel PROPERTY C_STANDARD 11)

target_include_directories(ziti-edge-tunnel
        PRIVATE include
        )

target_compile_definitions(ziti-edge-tunnel
        PRIVATE GIT_VERSION=${GIT_VERSION}
        PRIVATE ZITI_LOG_PREFIX=${PROJECT_NAME}
        )

target_link_libraries(ziti-edge-tunnel
        PUBLIC ziti ziti-tunnel-sdk-c ziti-tunnel-cbs-c
        PUBLIC lwipcore ${lwip_sys_lib} ziti-tunnel-sdk-c ${tun_lib}
        PUBLIC subcommand ${getopt}
        )

BUNDLE_COMP(ziti-edge-tunnel)

install(TARGETS ziti-edge-tunnel
        DESTINATION ${CMAKE_INSTALL_BINDIR}
        )
