/*
 Copyright 2025 NetFoundry Inc.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

#ifndef UNDERLAY_H_INCLUDED
#define UNDERLAY_H_INCLUDED

#include <stdbool.h>
#include "uv.h"

typedef struct underlay_s underlay_t;

typedef struct underlay_handle_s {
    void *              handle;
    const underlay_t *  impl;
} underlay_conn_t;

typedef void*(*underlay_get_data_fn)(underlay_conn_t *c);
typedef void(*underlay_set_data_fn)(underlay_conn_t *c, void *data);
typedef bool(*underlay_is_ok_fn)(int e);
typedef const char*(*underlay_strerror_fn)(int err);
typedef int(*underlay_bind_fn)(underlay_conn_t *c, const struct sockaddr *addr, int flags);
typedef void(*underlay_connected_fn)(underlay_conn_t *c, int status);
typedef int(*underlay_connect_fn)(underlay_conn_t *c, const struct sockaddr *addr, underlay_connected_fn on_connect);
typedef void(*underlay_closed_fn)(underlay_conn_t *c);
typedef void(*underlay_close_fn)(underlay_conn_t *c, underlay_closed_fn on_close);

struct underlay_s {
    underlay_get_data_fn get_data;
    underlay_set_data_fn set_data;
    underlay_is_ok_fn    is_ok;
    underlay_strerror_fn strerror;
    underlay_bind_fn     bind;
    underlay_connect_fn  connect;
    underlay_close_fn    close;
};

underlay_conn_t *underlay_uv_tcp_init(uv_loop_t *loop, char *err, size_t err_sz);
underlay_conn_t *underlay_uv_udp_init(uv_loop_t *loop, char *err, size_t err_sz);

underlay_conn_t *underlay_lwip_tcp_init();
underlay_conn_t *underlay_lwip_udp_init();

#endif // UNDERLAY_H_INCLUDED