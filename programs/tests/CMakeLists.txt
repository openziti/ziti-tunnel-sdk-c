project(tests)

add_executable(ziti-edge-tunnel-test ziti-edge-tunnel-test.c)
set_property(TARGET ziti-edge-tunnel-test PROPERTY C_STANDARD 11)

target_link_libraries(ziti-edge-tunnel-test
        PUBLIC uv_a
        )

BUNDLE_COMP(ziti-edge-tunnel-test)

install(TARGETS ziti-edge-tunnel-test
        DESTINATION ${CMAKE_INSTALL_BINDIR}
        )