add_library(ziti_tunneler STATIC
        ziti_tunneler.c
        ${PROJECT_SOURCE_DIR}/include/nf/ziti_tunneler.h
        lwip/netif_shim.c lwip/lwiphooks.c)

target_link_libraries(ziti_tunneler
        PUBLIC ziti
        PUBLIC lwipcontribportunix
        PUBLIC lwipcore
        )

string(LENGTH "${CMAKE_SOURCE_DIR}/" SOURCE_PATH_SIZE)
add_definitions("-DSOURCE_PATH_SIZE=${SOURCE_PATH_SIZE}")

set (LWIP_DIR "${CMAKE_SOURCE_DIR}/deps/lwip")
set (LWIP_CONTRIB_DIR "${CMAKE_SOURCE_DIR}/deps/lwip-contrib")
set (LWIP_INCLUDE_DIRS
        "${LWIP_DIR}/src/include"
        "${LWIP_CONTRIB_DIR}/ports/unix/port/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/lwip"
        )

include(${LWIP_DIR}/src/Filelists.cmake)
include(${LWIP_CONTRIB_DIR}/ports/unix/Filelists.cmake)

target_include_directories(ziti_tunneler
        PUBLIC ${LWIP_INCLUDE_DIRS}
        PUBLIC ../include
        PRIVATE ../include/priv
        )