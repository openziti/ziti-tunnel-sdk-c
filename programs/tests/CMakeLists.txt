project(tests)

add_executable(ziti-edge-tunnel-test ziti-edge-tunnel-test.c)
set_property(TARGET ziti-edge-tunnel-test PROPERTY C_STANDARD 11)

find_package(libuv CONFIG QUIET)
if (libuv_FOUND)
        # newer libuv versions have proper namespacing
        if (TARGET libuv::uv_a)
                set(libuv_lib libuv::uv_a)
        elseif (TARGET uv_a)
                set(libuv_lib uv_a)
        elseif (TARGET libuv::uv)
                set(libuv_lib libuv::uv)
        else()
                set(libuv_lib uv)
        endif()
else()
        find_library(libuv_lib uv_a NAMES uv)
endif()

target_link_libraries(ziti-edge-tunnel-test
        PUBLIC ${libuv_lib}
        )

install(TARGETS ziti-edge-tunnel-test
        DESTINATION ${CMAKE_INSTALL_BINDIR}
        )