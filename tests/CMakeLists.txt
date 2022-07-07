add_executable(all_tests
        all_tests.cpp
)

if (WIN32)
    set_property(TARGET all_tests PROPERTY CXX_STANDARD 20)
else ()
    set_property(TARGET all_tests PROPERTY CXX_STANDARD 11)
endif ()

target_include_directories(all_tests
        PUBLIC ${ziti-tunnel-sdk-c_SOURCE_DIR}/tests)

# include tests from within the project
target_link_libraries(all_tests
        PUBLIC ziti-tunnel-cbs-c-test-lib
        PUBLIC ziti-tunnel-sdk-c-test-lib
)

include(CTest)
add_test(quick_tests all_tests -d yes)