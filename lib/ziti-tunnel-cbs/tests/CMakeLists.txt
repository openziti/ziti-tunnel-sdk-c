enable_testing()

# package tests into a library so they can be referenced in all_tests
add_library(ziti-tunnel-cbs-c-test-lib OBJECT
        dns_test.cpp
)

target_include_directories(ziti-tunnel-cbs-c-test-lib
        PUBLIC ${ziti-tunnel-sdk-c_SOURCE_DIR}/tests
)

target_link_libraries(ziti-tunnel-cbs-c-test-lib
        PUBLIC ziti
        PUBLIC ziti-tunnel-cbs-c
)

add_executable(ziti-tunnel-cbs-c-test-runner
        tunnel_cbs_tests.cpp
)

target_link_libraries(ziti-tunnel-cbs-c-test-runner
        PUBLIC ziti-tunnel-cbs-c-test-lib
)

if (WIN32)
    set_property(TARGET ziti-tunnel-cbs-c-test-runner ziti-tunnel-cbs-c-test-lib PROPERTY CXX_STANDARD 20)
else ()
    set_property(TARGET ziti-tunnel-cbs-c-test-runner ziti-tunnel-cbs-c-test-lib PROPERTY CXX_STANDARD 11)
endif ()

include(CTest)
add_test(quick_tests ziti-tunnel-cbs-c-test-runner -d yes)