

FetchContent_Declare(wintun
        URL      https://www.wintun.net/builds/wintun-0.14.1.zip
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)

FetchContent_MakeAvailable(wintun)

add_library(wintun INTERFACE)
target_include_directories(wintun INTERFACE ${wintun_SOURCE_DIR}/include)
