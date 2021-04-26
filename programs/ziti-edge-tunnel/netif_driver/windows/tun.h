//
// Created by eugene on 4/21/2021.
//

#ifndef ZITI_TUNNEL_SDK_C_TUN_H
#define ZITI_TUNNEL_SDK_C_TUN_H


extern netif_driver tun_open(struct uv_loop_s *loop, uint32_t tun_ip, uint32_t dns_ip, const char *cidr, char *error, size_t error_len);

#endif //ZITI_TUNNEL_SDK_C_TUN_H
