#include <uv.h>

extern int ziti_tunnel_hosting_socket(uv_os_sock_t *, const struct addrinfo *ai);

int
ziti_tunnel_hosting_socket(uv_os_sock_t *sock, const struct addrinfo *ai)
{
    (void) sock;
    (void) ai;
    return UV_ENOSYS;
}
