if(CMAKE_SYSTEM_NAME STREQUAL Darwin OR CMAKE_SYSTEM_NAME STREQUAL Linux)
    project(ziti-edge-tunnel)

    if(CMAKE_SYSTEM_NAME STREQUAL Darwin)
        set(NETIF_DRIVER_SOURCE netif_driver/darwin/utun.c)
    endif()
    if(CMAKE_SYSTEM_NAME STREQUAL Linux)
        set(NETIF_DRIVER_SOURCE netif_driver/linux/tun.c)
    endif()

    add_executable(ziti-edge-tunnel ziti-edge-tunnel.c ${NETIF_DRIVER_SOURCE} dnsmasq_manager.c)
    set_property(TARGET ziti-edge-tunnel PROPERTY C_STANDARD 11)


    target_compile_definitions(ziti-edge-tunnel
            PRIVATE GIT_VERSION=${GIT_VERSION}
            PRIVATE ZITI_LOG_PREFIX=${PROJECT_NAME}
            )

    set(LWIP_MEM_SIZE 524288)
    set(LWIP_PBUF_POOL_SIZE 512)
    set(UDP_MAX_CONNECTIONS 64)
    set(TCP_MAX_CONNECTIONS 256)
    set(TCP_MAX_QUEUED_SEGMENTS 1024)

    # override LWIP defaults here
    target_compile_definitions(lwipcore
            PUBLIC MEM_SIZE=${LWIP_MEM_SIZE}
            PUBLIC PBUF_POOL_SIZE=${LWIP_PBUF_POOL_SIZE}
            PUBLIC MEMP_NUM_TCP_PCB=${TCP_MAX_CONNECTIONS}
            PUBLIC MEMP_NUM_TCP_SEG=${TCP_MAX_QUEUED_SEGMENTS}
            PUBLIC MEMP_NUM_UDP_PCB=${UDP_MAX_CONNECTIONS}
            )

    target_link_libraries(ziti-edge-tunnel
            PUBLIC ziti ziti-tunnel-sdk-c ziti-tunnel-cbs-c
            PUBLIC lwipcore ${lwip_sys_lib} ziti-tunnel-sdk-c
            PUBLIC subcommand
            )

    BUNDLE_COMP(ziti-edge-tunnel)
endif()