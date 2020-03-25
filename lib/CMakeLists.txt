add_library(ziti_tunneler STATIC
        ziti_tunneler.c lwipopts.h
        ${PROJECT_SOURCE_DIR}/include/nf/ziti_tunneler.h)

target_link_libraries(ziti_tunneler
        PUBLIC ziti
        PUBLIC lwipcore
        )

#set(LWIP_MBEDTLSDIR, )

set (LWIP_DIR "${CMAKE_SOURCE_DIR}/deps/lwip")
set (LWIP_CONTRIB_DIR "${LWIP_DIR}/contrib")
set (LWIP_INCLUDE_DIRS
        "${LWIP_DIR}/src/include"
        "${LWIP_DIR}/contrib/ports/unix/port/include"
        "${CMAKE_CURRENT_SOURCE_DIR}"
##        "<path to lwipopts.h>"
        )

include(${LWIP_DIR}/src/Filelists.cmake)
include(${LWIP_DIR}/contrib/ports/unix/Filelists.cmake)

target_include_directories(ziti_tunneler
        PUBLIC ../include
        )