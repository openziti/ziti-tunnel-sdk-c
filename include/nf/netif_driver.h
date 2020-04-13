#ifndef ZITI_TUNNELER_SDK_NETIF_DRIVER_H
#define ZITI_TUNNELER_SDK_NETIF_DRIVER_H

#include <sys/types.h>
#include "uv.h"

/* this struct is defined by the netif implementation */
typedef struct netif_handle_s *netif_handle;

typedef int (*netif_close_cb)(netif_handle dev);
typedef ssize_t (*netif_read_cb)(netif_handle dev, void *buf, size_t buf_len);
typedef ssize_t (*netif_write_cb)(netif_handle dev, const void *buf, size_t len);

typedef uv_poll_t * (*uv_poll_req_fn)(netif_handle dev, uv_loop_t *loop);

typedef struct netif_driver_s {
    netif_handle   handle;
    netif_read_cb  read;
    netif_write_cb write;
    netif_close_cb close;
    uv_poll_req_fn uv_poll_init;
} *netif_driver;

#endif //ZITI_TUNNELER_SDK_NETIF_DRIVER_H
