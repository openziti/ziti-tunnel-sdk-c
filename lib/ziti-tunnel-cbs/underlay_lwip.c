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


#include "underlay.h"

#include "lwip/tcp.h"
#include "lwip/udp.h"

static const underlay_t underlay_lwip_tcp = {
        .get_data = NULL,
        .set_data = NULL,
        .is_ok = NULL,
        .strerror = NULL,
        .connect = NULL,
        .bind = NULL,
        .close = NULL
};

underlay_conn_t *underlay_lwip_tcp_init() {
    underlay_conn_t *conn = calloc(1, sizeof(underlay_conn_t));
    conn->handle = tcp_new();
    conn->impl = &underlay_lwip_tcp;
    return conn;
}


static const underlay_t underlay_lwip_udp = {
        .get_data = NULL,
        .set_data = NULL,
        .is_ok = NULL,
        .strerror = NULL,
        .connect = NULL,
        .bind = NULL,
        .close = NULL
};

underlay_conn_t *underlay_lwip_udp_init() {
    underlay_conn_t *conn = calloc(1, sizeof(underlay_conn_t));
    conn->handle = udp_new();
    conn->impl = &underlay_lwip_udp;
    return conn;
}