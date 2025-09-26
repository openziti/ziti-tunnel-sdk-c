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

#include <stdlib.h>
#include "underlay.h"

static void *underlay_uv_get_data(underlay_conn_t *c) {
    uv_handle_t *uv_h = c->handle;
    return uv_h->data;
}

static void underlay_uv_set_data(underlay_conn_t *c, void *data) {
    uv_handle_t *uv_h = c->handle;
    uv_h->data = data;
}

static bool underlay_uv_is_ok(int e) {
    return e == 0;
}

static const char *underlay_uv_strerror(int err) {
    static char err_str[256];
    snprintf(err_str, sizeof(err_str), "libuv: %s (e=%d)", uv_strerror(err), err);
    return err_str;
}

static int underlay_uv_tcp_bind(underlay_conn_t *c, const struct sockaddr *addr, int flags) {
    int e = uv_tcp_bind(c->handle, addr, flags);
    return e;
}

struct on_tcp_connect_data {
    underlay_conn_t *      c;
    underlay_connected_fn  on_connect;
};

static void on_tcp_connect_wrapper(uv_connect_t *req, int status) {
    struct on_tcp_connect_data *ocd = req->data;
    ocd->on_connect(ocd->c, status);
    free(ocd);
    free(req);
}

static int underlay_uv_tcp_connect(underlay_conn_t *c, const struct sockaddr *addr, underlay_connected_fn on_connect) {
    uv_connect_t *req = calloc(1, sizeof(uv_connect_t));
    struct on_tcp_connect_data *ocd = req->data = calloc(1, sizeof(struct on_tcp_connect_data));
    ocd->c = c;
    ocd->on_connect = on_connect;

    int e = uv_tcp_connect(req, c->handle, addr, on_tcp_connect_wrapper);
    if (e != 0) {
        free(ocd);
        free(req);
    }
    return e;
}

struct on_close_data_s {
    void *              data;
    underlay_conn_t *   c;
    underlay_closed_fn  on_close;
};

// replace data pointer and call close cb if any
static void on_close_wrapper(uv_handle_t *h) {
    struct on_close_data_s *ocd = h->data;
    if (ocd->on_close) {
        h->data = ocd->data;
        ocd->on_close(ocd->c);
    }
    free(ocd->c);
    free(ocd);
}

static void underlay_uv_close(underlay_conn_t *c, underlay_closed_fn on_close) {
    uv_handle_t *uv_h = c->handle;
    if (!uv_is_closing(uv_h)) {
        struct on_close_data_s *ocd = calloc(1, sizeof(struct on_close_data_s));
        ocd->data = uv_h->data;
        ocd->c = c;
        ocd->on_close = on_close;
        uv_h->data = ocd;
        uv_close(uv_h, on_close_wrapper);
    }
}

static const underlay_t underlay_uv_tcp = {
        .get_data = underlay_uv_get_data,
        .set_data = underlay_uv_set_data,
        .is_ok = underlay_uv_is_ok,
        .strerror = underlay_uv_strerror,
        .connect = underlay_uv_tcp_connect,
        .bind = underlay_uv_tcp_bind,
        .close = underlay_uv_close
};

underlay_conn_t *underlay_uv_tcp_init(uv_loop_t *loop, char *err, size_t err_sz) {
    underlay_conn_t *conn = calloc(1, sizeof(underlay_conn_t));
    conn->impl = &underlay_uv_tcp;

    uv_tcp_t *tcp = conn->handle = calloc(1, sizeof(uv_tcp_t));
    int e = uv_tcp_init(loop, tcp);
    if (e != 0) {
        if (err != NULL && err_sz > 0) {
            snprintf(err, err_sz, "uv_tcp_init: err=%d %s", e, uv_strerror(e));
        }
        free(conn->handle); conn->handle = NULL;
        free(conn); conn = NULL;
    }
    return conn;
}

static int underlay_uv_udp_bind(underlay_conn_t *c, const struct sockaddr *addr, int flags) {
    int e = uv_udp_bind(c->handle, addr, flags);
    return e;
}

static int underlay_uv_udp_connect(underlay_conn_t *c, const struct sockaddr *addr, underlay_connected_fn on_connect) {
    int e = uv_udp_connect(c->handle, addr);
    on_connect(c->handle, e);
    return e;
}

static const underlay_t underlay_uv_udp = {
        .get_data = underlay_uv_get_data,
        .set_data = underlay_uv_set_data,
        .is_ok = underlay_uv_is_ok,
        .strerror = underlay_uv_strerror,
        .bind = underlay_uv_udp_bind,
        .connect = underlay_uv_udp_connect,
        .close = underlay_uv_close
};

underlay_conn_t *underlay_uv_udp_init(uv_loop_t *loop, char *err, size_t err_sz) {
    underlay_conn_t *conn = calloc(1, sizeof(underlay_conn_t));
    conn->impl = &underlay_uv_udp;

    uv_udp_t *udp = conn->handle = calloc(1, sizeof(uv_udp_t));
    int e = uv_udp_init(loop, udp);
    if (e != 0) {
        if (err != NULL && err_sz > 0) {
            snprintf(err, err_sz, "uv_udp_init failed: %s", uv_strerror(e));
        }
        free(conn->handle); conn->handle = NULL;
        free(conn); conn = NULL;
    }
    return conn;
}
