project(ziti-tunneler-sdk-deps)

include(FetchContent)

FetchContent_Declare(ziti-sdk-c
        GIT_REPOSITORY https://github.com/openziti/ziti-sdk-c.git
        GIT_TAG 0.15.7
        )
FetchContent_MakeAvailable(ziti-sdk-c)
