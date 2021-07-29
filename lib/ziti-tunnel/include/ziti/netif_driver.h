#ifndef ZITI_TUNNELER_SDK_NETIF_DRIVER_H
#define ZITI_TUNNELER_SDK_NETIF_DRIVER_H

#include <sys/types.h>
#include "uv.h"

/* this struct is defined by the netif implementation */
typedef struct netif_handle_s *netif_handle;

// see on_packet()
typedef void (*packet_cb)(const char *buf, ssize_t len, void *netif);

typedef int (*netif_close_cb)(netif_handle dev);
typedef ssize_t (*netif_read_cb)(netif_handle dev, void *buf, size_t buf_len);
typedef ssize_t (*netif_write_cb)(netif_handle dev, const void *buf, size_t len);
typedef int (*uv_poll_req_fn)(netif_handle dev, uv_loop_t *loop, uv_poll_t *tun_poll_req);
typedef int (*setup_packet_cb)(netif_handle dev, uv_loop_t *loop, packet_cb cb, void *netif);
typedef int (*add_route_cb)(netif_handle dev, const char *dest);
typedef int (*delete_route_cb)(netif_handle dev, const char *dest);
typedef int (*exclude_route_fn)(netif_handle dev, uv_loop_t *loop, const char *dest);

typedef struct netif_driver_s {
    netif_handle handle;
    netif_read_cb read;
    netif_write_cb write;
    netif_close_cb close;
    uv_poll_req_fn uv_poll_init;
    setup_packet_cb setup;
    add_route_cb add_route;
    delete_route_cb delete_route;
    exclude_route_fn exclude_rt;
} netif_driver_t;
typedef netif_driver_t *netif_driver;

extern int prefix_to_ipv4_subnet(int prefix_len, char *subnet, size_t subnet_sz);

#endif //ZITI_TUNNELER_SDK_NETIF_DRIVER_H
