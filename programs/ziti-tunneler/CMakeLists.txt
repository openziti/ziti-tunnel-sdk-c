project(ziti-tunneler-app)

if(CMAKE_SYSTEM_NAME STREQUAL Darwin)
    set(NETIF_DRIVER_SOURCE netif_driver/darwin/utun.c)
endif()
if(CMAKE_SYSTEM_NAME STREQUAL Linux)
    set(NETIF_DRIVER_SOURCE netif_driver/linux/tun.c)
endif()

add_executable(ziti-tunneler-app ziti-tunneler.c ziti-tunneler-cbs.c ${NETIF_DRIVER_SOURCE})

target_link_libraries(ziti-tunneler-app
        PUBLIC ziti ziti_tunneler
        PUBLIC lwipcore lwipcontribportunix ziti_tunneler)