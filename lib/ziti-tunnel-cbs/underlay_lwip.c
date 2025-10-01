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
#include "ziti/ziti_tunnel.h"
#include "../ziti-tunnel/tunnel_udp.h"

static bool underlay_lwip_is_ok(int e) {
    return e == ERR_OK;
}

static const char *underlay_lwip_strerror(int e) {
    static char err_str[256];
    static const char *err_strerr[] = {
            "Ok.",                    /* ERR_OK          0  */
            "Out of memory error.",   /* ERR_MEM        -1  */
            "Buffer error.",          /* ERR_BUF        -2  */
            "Timeout.",               /* ERR_TIMEOUT    -3  */
            "Routing problem.",       /* ERR_RTE        -4  */
            "Operation in progress.", /* ERR_INPROGRESS -5  */
            "Illegal value.",         /* ERR_VAL        -6  */
            "Operation would block.", /* ERR_WOULDBLOCK -7  */
            "Address in use.",        /* ERR_USE        -8  */
            "Already connecting.",    /* ERR_ALREADY    -9  */
            "Already connected.",     /* ERR_ISCONN     -10 */
            "Not connected.",         /* ERR_CONN       -11 */
            "Low-level netif error.", /* ERR_IF         -12 */
            "Connection aborted.",    /* ERR_ABRT       -13 */
            "Connection reset.",      /* ERR_RST        -14 */
            "Connection closed.",     /* ERR_CLSD       -15 */
            "Illegal argument."       /* ERR_ARG        -16 */
    }; // copied from lwip/src/api/err.c to avoid defining LWIP_DEBUG

    int i = e * -1;
    snprintf(err_str, sizeof(err_str), "lwip: %s (e=%d)", err_strerr[i], e);
    return err_str;
}

static const underlay_t underlay_lwip_tcp = {
        .get_data = NULL,
        .set_data = NULL,
        .is_ok = underlay_lwip_is_ok,
        .strerror = underlay_lwip_strerror,
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

static void *underlay_lwip_udp_get_data(underlay_conn_t *c) {
    struct udp_pcb *pcb = c->handle;
    return pcb->recv_arg;
}

static void underlay_lwip_udp_set_data(underlay_conn_t *c, void *data) {
    struct udp_pcb *pcb = c->handle;
    pcb->recv_arg = data;
}

static int underlay_lwip_udp_bind(underlay_conn_t *c, const struct sockaddr *addr, int flags) {
    LWIP_UNUSED_ARG(flags);
    struct udp_pcb *pcb = c->handle;
    ip_addr_t local_ip;
    u16_t local_port;
    if (!ip_addr_from_sockaddr(&local_ip, &local_port, addr)) {
        return ERR_VAL;
    }
    ip_addr_set_ipaddr(&pcb->local_ip, &local_ip);
    pcb->local_port = local_port;
    err_t e = ERR_OK; //udp_bind(pcb, &local_ip, local_port);
    return e;
}

static int underlay_lwip_udp_connect(underlay_conn_t *c, const struct sockaddr *addr, underlay_connected_fn on_connect) {
    ip_addr_t dst_ip;
    u16_t dst_port;
    if (!ip_addr_from_sockaddr(&dst_ip, &dst_port, addr)) {
        return ERR_VAL;
    }
    err_t e = udp_connect(c->handle, &dst_ip, dst_port);
    on_connect(c, e);
    return e;
}

static void underlay_lwip_udp_close(underlay_conn_t *c, underlay_closed_fn on_close) {
    struct udp_pcb *pcb = c->handle;
    tunneler_udp_close(pcb);
    on_close(c);
}

static const underlay_t underlay_lwip_udp = {
        .get_data = underlay_lwip_udp_get_data,
        .set_data = underlay_lwip_udp_set_data,
        .is_ok = underlay_lwip_is_ok,
        .strerror = underlay_lwip_strerror,
        .bind = underlay_lwip_udp_bind,
        .connect = underlay_lwip_udp_connect,
        .close = underlay_lwip_udp_close
};

underlay_conn_t *underlay_lwip_udp_init(const struct netif *netif) {
    struct udp_pcb *pcb = udp_new();
    if (pcb == NULL) {
        // todo propagate error
        return NULL;
    }
    udp_bind_netif(pcb, netif);
    underlay_conn_t *conn = calloc(1, sizeof(underlay_conn_t));
    conn->handle = pcb;
    conn->impl = &underlay_lwip_udp;
    return conn;
}