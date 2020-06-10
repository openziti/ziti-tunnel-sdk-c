
add_library(ziti_tunneler STATIC
        ziti_tunneler.c tunneler_tcp.c tunneler_udp.c intercept.c
        lwip/netif_shim.c lwip/lwiphooks_ip6.c lwip/lwiphooks_ip4.c)

add_library(ziti_tunneler_cbs STATIC ziti_tunneler_cbs.c)

target_include_directories(ziti_tunneler_cbs
        PUBLIC ../include
        )

target_link_libraries(ziti_tunneler_cbs
        PUBLIC ziti
        )

set (LWIP_DIR "${CMAKE_SOURCE_DIR}/deps/lwip")
set (LWIP_CONTRIB_DIR "${CMAKE_SOURCE_DIR}/deps/lwip-contrib")

if(WIN32)
    set(LWIP_CONTRIB_INCLUDE "${LWIP_CONTRIB_DIR}/ports/win32/include")
    set(lwip_sys "win32")
    set(lwip_sys_lib "lwipwin32arch")
    set(lwip_sys_srcs ${LWIP_CONTRIB_DIR}/ports/win32/sys_arch.c)
else()
    set(LWIP_CONTRIB_INCLUDE "${LWIP_CONTRIB_DIR}/ports/unix/port/include")
    set(lwip_sys "unix")
    set(lwip_sys_lib "lwipunixarch")
    set(lwip_sys_srcs ${LWIP_CONTRIB_DIR}/ports/unix/port/sys_arch.c)
endif()

set (LWIP_INCLUDE_DIRS
        "${LWIP_DIR}/src/include"
        "${LWIP_CONTRIB_INCLUDE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/lwip"
        )

include(${LWIP_DIR}/src/Filelists.cmake)

target_include_directories(ziti_tunneler
        PUBLIC ${LWIP_INCLUDE_DIRS}
        PUBLIC ../include
        PRIVATE ../include/priv
        PRIVATE ${ziti-tunneler-sdk-deps_SOURCE_DIR}
        )

add_library(${lwip_sys_lib} STATIC
        ${lwip_sys_srcs})

target_include_directories(${lwip_sys_lib}
        PUBLIC ${LWIP_INCLUDE_DIRS}
        )

target_link_libraries(ziti_tunneler
        PUBLIC ziti
        PUBLIC ${lwip_sys_lib}
        PUBLIC lwipcore
        )
