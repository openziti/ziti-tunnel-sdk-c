enable_testing()

add_library(ziti-edge-tunnel-test-lib OBJECT
        app_info_test.cpp
        ../app-info.c
)

# app-info.c is compiled again here rather than reused from the ziti-edge-tunnel target, so the
# registry read can be aimed at a key the tests own and can write without elevation.
target_compile_definitions(ziti-edge-tunnel-test-lib
        PRIVATE INSTALL_REG_ROOT=HKEY_CURRENT_USER
        PRIVATE INSTALL_REG_KEY="SOFTWARE\\\\ziti-edge-tunnel-test\\\\app-info"
        PRIVATE ZITI_LOG_MODULE="ziti-edge-tunnel-test"
)

target_include_directories(ziti-edge-tunnel-test-lib
        PUBLIC ${ziti-tunnel-sdk-c_SOURCE_DIR}/tests
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

target_link_libraries(ziti-edge-tunnel-test-lib
        PUBLIC ziti
)

if (WIN32)
    set_property(TARGET ziti-edge-tunnel-test-lib PROPERTY CXX_STANDARD 20)
else ()
    set_property(TARGET ziti-edge-tunnel-test-lib PROPERTY CXX_STANDARD 11)
endif ()

set_property(TARGET ziti-edge-tunnel-test-lib PROPERTY C_STANDARD 11)
