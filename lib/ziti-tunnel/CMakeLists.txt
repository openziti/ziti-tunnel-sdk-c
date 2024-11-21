
add_library(ziti-tunnel-sdk-c STATIC
        ziti_tunnel.c tunnel_tcp.c tunnel_udp.c intercept.c route.c
        lwip/netif_shim.c tunnel_log.c)

set_property(TARGET ziti-tunnel-sdk-c PROPERTY C_STANDARD 11)

target_compile_definitions(ziti-tunnel-sdk-c
        PRIVATE GIT_VERSION=${GIT_VERSION}
        PRIVATE BUILD_DATE=${BUILD_DATE}
        PRIVATE ZITI_LOG_PREFIX=${PROJECT_NAME}
        )

FetchContent_GetProperties(lwip)
set (LWIP_DIR "${lwip_SOURCE_DIR}")
set (LWIP_CONTRIB_DIR "${lwip_SOURCE_DIR}/contrib")

if(WIN32)
    set(LWIP_CONTRIB_INCLUDE "${LWIP_CONTRIB_DIR}/ports/win32/include")
    set(lwip_sys "win32")
    set(lwip_sys_srcs ${LWIP_CONTRIB_DIR}/ports/win32/sys_arch.c)
else()
    set(LWIP_CONTRIB_INCLUDE "${LWIP_CONTRIB_DIR}/ports/unix/port/include")
    set(lwip_sys "unix")
    set(lwip_sys_srcs ${LWIP_CONTRIB_DIR}/ports/unix/port/sys_arch.c)
endif()

if (ANDROID)
    set(platform_lwip_include ${CMAKE_CURRENT_SOURCE_DIR}/lwip/ports/android)
endif ()
set (LWIP_INCLUDE_DIRS
        "${platform_lwip_include}"
        "${LWIP_DIR}/src/include"
        "${LWIP_CONTRIB_INCLUDE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/lwip"
        )

include(${LWIP_DIR}/src/Filelists.cmake)

target_sources(lwipcore PRIVATE ${lwip_sys_srcs} lwip/lwiphooks_ip6.c lwip/lwiphooks_ip4.c lwip/lwip_cloned_fns.c)
target_compile_definitions(lwipcore PUBLIC CMAKE_C_BYTE_ORDER=${CMAKE_C_BYTE_ORDER})

target_include_directories(ziti-tunnel-sdk-c
        PUBLIC ${LWIP_INCLUDE_DIRS}
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
        PRIVATE ${ziti-tunnel-sdk-c-deps_SOURCE_DIR}
        )

target_link_libraries(ziti-tunnel-sdk-c
        PUBLIC ziti
        PUBLIC lwipcore
        )

#copy relevant .h files to the include folder
install(DIRECTORY "${LWIP_DIR}/src/include/lwip"
     DESTINATION "${CMAKE_INSTALL_PREFIX}/include"
     FILES_MATCHING PATTERN "*.h"
)
install(DIRECTORY "${LWIP_CONTRIB_DIR}/ports/${lwip_sys}/include/arch"
     DESTINATION "${CMAKE_INSTALL_PREFIX}/include"
     FILES_MATCHING PATTERN "*.h"
)
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/lwip/lwipopts.h"
     DESTINATION "${CMAKE_INSTALL_PREFIX}/include"
)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
        DESTINATION ${CMAKE_INSTALL_PREFIX}/include)

install(TARGETS lwipcore ziti-tunnel-sdk-c
        DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
        )

if(ZITI_TUNNEL_BUILD_TESTS)
  add_subdirectory(tests)
endif()