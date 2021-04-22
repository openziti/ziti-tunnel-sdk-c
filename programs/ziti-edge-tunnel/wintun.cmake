

FetchContent_Declare(wintun
        URL      https://www.wintun.net/builds/wintun-0.10.3.zip
        URL_HASH SHA256=97de836805006c39c3c6ddf57bac0707d096cc88a9ca0b552cb95f1de08da060
)

FetchContent_GetProperties(wintun)
if(NOT wintun_POPULATED)
    FetchContent_Populate(wintun)
endif()

add_library(wintun INTERFACE)
target_include_directories(subcommand INTERFACE ${wintun_SOURCE_DIR}/include)
