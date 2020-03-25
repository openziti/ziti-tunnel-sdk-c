project(ziti-tunneler-app)

add_executable(ziti-tunneler-app ziti-tunneler.c tun_darwin.c)

target_link_libraries(ziti-tunneler-app
        PUBLIC ziti
        PUBLIC ziti_tunneler)