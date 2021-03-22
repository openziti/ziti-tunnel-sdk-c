

target_compile_definitions(ziti-tunnel-sdk-c
        PRIVATE GIT_VERSION=${GIT_VERSION}
        PRIVATE ZITI_LOG_PREFIX=${PROJECT_NAME}
        )

add_library(ziti-tunnel-cbs-c STATIC ziti_tunnel_cbs.c ziti_hosting.c ziti_tunnel_ctrl.c)

target_include_directories(ziti-tunnel-cbs-c
        PUBLIC include
        )

target_link_libraries(ziti-tunnel-cbs-c
        PUBLIC ziti
        PUBLIC ziti-tunnel-sdk-c
        )

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(TARGETS ziti-tunnel-cbs-c
        DESTINATION ${CMAKE_INSTALL_LIBDIR}
        )