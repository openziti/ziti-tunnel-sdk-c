

#include <stdint.h>
#include <ziti/netif_driver.h>

#define _Out_cap_c_(n)
#define _Ret_bytecount_(n)

#include <wintun.h>

#include "tun.h"

netif_driver tun_open(struct uv_loop_s *loop, uint32_t tun_ip, uint32_t dns_ip, const char *cidr, char *error, size_t error_len) {
    strcpy_s(error, error_len, "TODO: Implement me!");
    return NULL;
}
