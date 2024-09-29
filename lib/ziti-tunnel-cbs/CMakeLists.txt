

target_compile_definitions(ziti-tunnel-sdk-c
        PRIVATE GIT_VERSION=${GIT_VERSION}
        PRIVATE ZITI_LOG_PREFIX=${PROJECT_NAME}
        )

add_library(ziti-tunnel-cbs-c STATIC
        ziti_tunnel_cbs.c
        ziti_hosting.c
        ziti_hosting_socket.c
        ziti_tunnel_ctrl.c
        ziti_instance.h
        ziti_dns.c
        dns_msg.c
        dns_host.c
        dns_host.h
        ziti_tunnel_model.c
)

target_compile_definitions(ziti-tunnel-cbs-c
        PRIVATE ZITI_LOG_MODULE="tunnel-cbs"
        )

target_include_directories(ziti-tunnel-cbs-c
        PUBLIC include
        )

if(MINGW)
    # mingw's linker is single-pass, and we get undefined symbols from libmbedtls for symbols in winsock2 without this
    # doing this here this is a bit of a hack, but I couldn't figure out how to influence cmake to get this right when
    # we get mbledtls from vcpkg.
    SET(socket_lib ws2_32)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL Windows)
    SET(resolve_lib dnsapi)
elseif(CMAKE_SYSTEM_NAME STREQUAL Android)
else()
    SET(resolve_lib resolv)
endif()

target_link_libraries(ziti-tunnel-cbs-c
        PUBLIC ziti
        PUBLIC ziti-tunnel-sdk-c
        PUBLIC ${resolve_lib} ${socket_lib}
        )

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
        DESTINATION ${CMAKE_INSTALL_PREFIX}/include)

install(TARGETS ziti-tunnel-cbs-c
        DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
        )

if(ZITI_TUNNEL_BUILD_TESTS)
  add_subdirectory(tests)
endif()
