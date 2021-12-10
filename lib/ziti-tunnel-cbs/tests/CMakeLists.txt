enable_testing()
add_executable(all_tests
        all_tests.cpp
        dns_test.cpp
)
if (WIN32)
    set_property(TARGET all_tests PROPERTY CXX_STANDARD 20)
else ()
    set_property(TARGET all_tests PROPERTY CXX_STANDARD 11)
endif ()

target_link_libraries(all_tests
        PUBLIC ziti
        PUBLIC ziti-tunnel-cbs-c)

include(CTest)
add_test(quick_tests all_tests -d yes)

