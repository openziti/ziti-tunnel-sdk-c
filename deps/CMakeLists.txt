include(FetchContent)

if(NOT TUNNEL_SDK_ONLY)

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

endif()

FetchContent_Declare(lwip
        GIT_REPOSITORY https://github.com/lwip-tcpip/lwip.git
        GIT_TAG STABLE-2_1_3_RELEASE
        )
FetchContent_GetProperties(lwip)
if(NOT lwip_POPULATED)
    FetchContent_Populate(lwip)
endif()

FetchContent_Declare(lwip-contrib
        GIT_REPOSITORY https://github.com/netfoundry/lwip-contrib.git
        GIT_TAG STABLE-2_1_0_RELEASE
        )
FetchContent_GetProperties(lwip-contrib)
if(NOT lwip-contrib_POPULATED)
    FetchContent_Populate(lwip-contrib)
endif()
