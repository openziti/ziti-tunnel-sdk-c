project(tests)

find_package(libuv CONFIG QUIET)
if (libuv_FOUND)
    if (TARGET uv_a)
        set(test_libuv_lib uv_a)
    else()
        set(test_libuv_lib uv)
    endif()
else()
    find_path(test_libuv_include_dir NAMES uv.h)
    find_library(test_libuv_lib uv_a NAMES uv)
endif()

add_executable(ziti-edge-tunnel-test ziti-edge-tunnel-test.c)
set_property(TARGET ziti-edge-tunnel-test PROPERTY C_STANDARD 11)

target_link_libraries(ziti-edge-tunnel-test
        PUBLIC ${test_libuv_lib}
        )

BUNDLE_COMP(ziti-edge-tunnel-test)

install(TARGETS ziti-edge-tunnel-test
        DESTINATION ${CMAKE_INSTALL_BINDIR}
        )