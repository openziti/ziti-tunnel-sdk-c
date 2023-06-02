include(FetchContent)

option(BUILD_SHARED_LIBS "" OFF)
option(BUILD_STATIC_LIBS "" ON)

if (NOT VCPKG_MANIFEST_MODE)
    message("configuring required dependencies")
    FetchContent_Declare(libuv
            GIT_REPOSITORY https://github.com/libuv/libuv
            GIT_TAG v1.45.0
            OVERRIDE_FIND_PACKAGE
    )
    FetchContent_MakeAvailable(libuv)

    FetchContent_Declare(llhttp
            GIT_REPOSITORY https://github.com/nodejs/llhttp
            GIT_TAG release/v8.1.0
            # fix for https://github.com/nodejs/llhttp/issues/222
            PATCH_COMMAND git apply ${CMAKE_CURRENT_SOURCE_DIR}/patches/llhttp.patch
            UPDATE_DISCONNECTED 1
            OVERRIDE_FIND_PACKAGE
    )
    FetchContent_MakeAvailable(llhttp)
    if (NOT TARGET llhttp::llhttp_static)
        add_library(llhttp::llhttp_static ALIAS llhttp_static)
    endif ()

    FetchContent_Declare(
            libsodium
            GIT_REPOSITORY http://github.com/jedisct1/libsodium
            GIT_TAG stable
            OVERRIDE_FIND_PACKAGE
    )

    FetchContent_GetProperties(libsodium)
    if (NOT libsodium_POPULATED)
        FetchContent_Populate(libsodium)
        message("MAKE_DIRECTORY	${libsodium_BINARY_DIR}")

        if (NOT EXISTS ${libsodium_BINARY_DIR})
            file(MAKE_DIRECTORY ${libsodium_BINARY_DIR})
        endif ()
        if (NOT WIN32)
            if (NOT EXISTS ${unofficial-sodium_BINARY_DIR}/config.status)
                # first build on macos fails because CMake picks up xcode
                if (APPLE)
                    unset(ENV{CC})
                    unset(ENV{CXX})
                endif ()
                execute_process(
                        COMMAND "${libsodium_SOURCE_DIR}/configure" "--prefix=${libsodium_BINARY_DIR}"
                        --disable-opt --without-pthreads --with-pic --host=${triple}
                        --with-sysroot=${CMAKE_SYSROOT}
                        WORKING_DIRECTORY ${libsodium_BINARY_DIR}
                )
            endif ()
            execute_process(
                    COMMAND make -j4
                    WORKING_DIRECTORY ${libsodium_BINARY_DIR}
            )
            execute_process(
                    COMMAND make install
                    WORKING_DIRECTORY ${libsodium_BINARY_DIR}
            )
        endif ()
    endif ()

    add_library(sodium IMPORTED STATIC GLOBAL)
    target_include_directories(sodium INTERFACE ${libsodium_BINARY_DIR}/include)
    set_target_properties(sodium PROPERTIES IMPORTED_LOCATION ${libsodium_BINARY_DIR}/lib/libsodium.a)
endif ()

if (NOT TUNNEL_SDK_ONLY)

    if (ZITI_SDK_DIR)
        add_subdirectory(${ZITI_SDK_DIR} ${CMAKE_CURRENT_BINARY_DIR}/ziti-sdk)
    else ()
        FetchContent_Declare(ziti-sdk-c
                GIT_REPOSITORY https://github.com/openziti/ziti-sdk-c.git
                GIT_TAG ${ZITI_SDK_VERSION}
        )
        set(ZITI_BUILD_TESTS off)
        set(ZITI_BUILD_PROGRAMS off)
        FetchContent_MakeAvailable(ziti-sdk-c)
    endif ()

endif ()

FetchContent_Declare(lwip
        GIT_REPOSITORY https://github.com/lwip-tcpip/lwip.git
        GIT_TAG STABLE-2_1_3_RELEASE
)
FetchContent_GetProperties(lwip)
if (NOT lwip_POPULATED)
    FetchContent_Populate(lwip)
endif ()

FetchContent_Declare(lwip-contrib
        GIT_REPOSITORY https://github.com/netfoundry/lwip-contrib.git
        GIT_TAG STABLE-2_1_0_RELEASE
)
FetchContent_GetProperties(lwip-contrib)
if (NOT lwip-contrib_POPULATED)
    FetchContent_Populate(lwip-contrib)
endif ()
