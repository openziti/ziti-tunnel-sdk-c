enable_testing()

# package tests into a library so they can be referenced in all_tests
add_library(ziti-tunnel-sdk-c-test-lib OBJECT
        address_test.cpp
        )

target_include_directories(ziti-tunnel-sdk-c-test-lib
        PUBLIC ${ziti-tunnel-sdk-c_SOURCE_DIR}/tests
        PUBLIC ${ziti-tunnel-sdk-c_SOURCE_DIR}/lib/ziti-tunnel
        )

target_link_libraries(ziti-tunnel-sdk-c-test-lib
        PUBLIC ziti ziti-tunnel-sdk-c
        )

add_executable(ziti-tunnel-sdk-c-test-runner
        tunnel_test.cpp
        )

#target_include_directories(ziti-tunnel-sdk-c-test-runner
#        PUBLIC ${ziti-tunnel-sdk-c_SOURCE_DIR}/tests
#        PUBLIC ${ziti-tunnel-sdk-c_SOURCE_DIR}/lib/ziti-tunnel
#        )

target_link_libraries(ziti-tunnel-sdk-c-test-runner
        PUBLIC ziti-tunnel-sdk-c-test-lib
        )

if (WIN32)
    set_property(TARGET ziti-tunnel-sdk-c-test-runner ziti-tunnel-sdk-c-test-lib PROPERTY CXX_STANDARD 20)
else ()
    set_property(TARGET ziti-tunnel-sdk-c-test-runner ziti-tunnel-sdk-c-test-lib PROPERTY CXX_STANDARD 11)
endif ()

include(CTest)
add_test(quick_tests ziti-tunnel-sdk-c-test-runner -d yes)