
if (NOT TARGET subcommand)
    FetchContent_Declare(subcommand
            GIT_REPOSITORY https://github.com/openziti/subcommands.c.git
            GIT_TAG main
    )
    FetchContent_MakeAvailable(subcommand)
    add_library(subcommand INTERFACE)
    target_include_directories(subcommand INTERFACE ${subcommand_SOURCE_DIR})
endif ()

add_compile_definitions(DEFAULT_EXECUTABLE_NAME="ziti-edge-tunnel")
add_subdirectory(ziti-edge-tunnel)

