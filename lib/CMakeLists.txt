
add_library(ziti_tunneler STATIC
        ziti_tunneler.c dns-server.c
        lwip/netif_shim.c lwip/lwiphooks.c)



string(LENGTH "${CMAKE_SOURCE_DIR}/" SOURCE_PATH_SIZE)
add_definitions("-DSOURCE_PATH_SIZE=${SOURCE_PATH_SIZE}")

if(WIN32)
    set(lwip_sys "win32")
    set(lwip_sys_lib "lwipwin32arch")
else()
    set(lwip_sys "unix")
    set(lwip_sys_lib "lwipcontribportunix")
endif()

set (LWIP_DIR "${CMAKE_SOURCE_DIR}/deps/lwip")
set (LWIP_CONTRIB_DIR "${CMAKE_SOURCE_DIR}/deps/lwip-contrib")

if (WIN32)
    set(LWIP_CONTRIB_INCLUDE "${LWIP_CONTRIB_DIR}/ports/win32/include")
else()
    set(LWIP_CONTRIB_INCLUDE  "${LWIP_CONTRIB_DIR}/ports/unix/port/include")
endif()

set (LWIP_INCLUDE_DIRS
        "${LWIP_DIR}/src/include"
        "${LWIP_CONTRIB_INCLUDE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/lwip"
        )

include(${LWIP_DIR}/src/Filelists.cmake)
if (UNIX)
include(${LWIP_CONTRIB_DIR}/ports/${lwip_sys}/Filelists.cmake)
endif()

target_include_directories(ziti_tunneler
        PUBLIC ${LWIP_INCLUDE_DIRS}
        PUBLIC ../include
        PRIVATE ../include/priv
        )

add_library(lwipwin32arch STATIC
        ${LWIP_CONTRIB_DIR}/ports/win32/sys_arch.c)

target_include_directories(lwipwin32arch
        PUBLIC "${LWIP_DIR}/src/include"
        PUBLIC "${LWIP_CONTRIB_INCLUDE}"
        PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/lwip"
)

target_link_libraries(ziti_tunneler
        PUBLIC ziti
        PUBLIC ${lwip_sys_lib}
        PUBLIC lwipcore
        )