project(ziti-tunneler-app)


if(UNIX AND APPLE)
    set(NETIF_DRIVER_SOURCE netif_driver/darwin/utun.c)
endif()

add_executable(ziti-tunneler-app ziti-tunneler.c ${NETIF_DRIVER_SOURCE})

target_link_libraries(ziti-tunneler-app
        PUBLIC ziti
        PUBLIC ziti_tunneler)