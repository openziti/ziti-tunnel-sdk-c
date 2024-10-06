

FetchContent_Declare(wintun
        URL      https://www.wintun.net/builds/wintun-0.14.1.zip
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)

FetchContent_GetProperties(wintun)
if(NOT wintun_POPULATED)
    FetchContent_Populate(wintun)
endif()

add_library(wintun INTERFACE)
target_include_directories(wintun INTERFACE ${wintun_SOURCE_DIR}/include)
