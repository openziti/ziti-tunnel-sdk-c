cmake_minimum_required(VERSION 3.16)
project(dcp_tools C)

set(CMAKE_C_STANDARD 11)

# ---------- platform raw-socket implementation ----------

if(WIN32)
    set(RAWSOCK_SRC rawsock_windows.c)
    set(RAWSOCK_LIBS iphlpapi ws2_32)
elseif(APPLE)
    set(RAWSOCK_SRC rawsock_macos.c)
    set(RAWSOCK_LIBS "")
else()
    # Linux (and other POSIX with AF_PACKET)
    set(RAWSOCK_SRC rawsock_linux.c)
    set(RAWSOCK_LIBS "")
endif()

# ---------- dcp_identify ----------

add_executable(dcp_identify
    dcp_identify.c
    ${RAWSOCK_SRC}
)
target_include_directories(dcp_identify PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(dcp_identify PRIVATE ${RAWSOCK_LIBS})

# ---------- dcp_respond ----------

add_executable(dcp_respond
    dcp_respond.c
    ${RAWSOCK_SRC}
)
target_include_directories(dcp_respond PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(dcp_respond PRIVATE ${RAWSOCK_LIBS})

# ---------- install ----------

install(TARGETS dcp_identify dcp_respond RUNTIME DESTINATION bin)
