#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "uv.h"
#include "nf/ziti.h"
#include "nf/ziti_tunneler.h"
#if __APPLE__ && __MACH__
#include "netif_driver/darwin/utun.h"
#else
#error "please port this file to your operating system"
#endif

/** context passed through the tunneler SDK */
typedef struct ziti_ctx_s {
    void *  nf_ctx;
} ziti_context;

/** context passed through the tunneler SDK for network i/o */
typedef struct ziti_io_ctx_s {
    ziti_conn_state      state;
    nf_connection        nf_conn;
    tunneler_io_context  tnlr_io_ctx;
} ziti_io_context;

void on_ziti_connect(nf_connection conn, int status) {
    fprintf(stderr, "on_ziti_connect status: %d\n", status);
    ziti_io_context *ziti_io_ctx = NF_conn_data(conn);
    if (status == ZITI_OK) {
        ziti_io_ctx->state = ZITI_CONNECTED;
    } else {
        ziti_io_ctx->state = ZITI_FAILED;
        free(ziti_io_ctx);
    }
}

void on_ziti_data(nf_connection conn, uint8_t *data, int len) {
    fprintf(stderr, "on_ziti_data: %x %d bytes!\n", data, len);
    ziti_io_context *ziti_io_ctx = NF_conn_data(conn);
    if (data > 0) {
        NF_tunneler_write(ziti_io_ctx->tnlr_io_ctx, data, len);
    } else {
        NF_tunneler_close(ziti_io_ctx->tnlr_io_ctx);
        free(ziti_io_ctx);
    }
}

/** called by tunneler SDK after a client connection is closed */
void my_ziti_close(const void *ziti_io_ctx) {
    ziti_io_context *_ziti_io_ctx = ziti_io_ctx;
    NF_close(&_ziti_io_ctx->nf_conn);
    free(ziti_io_ctx);
}

/** called by tunneler SDK after a client connection is intercepted */
void * my_ziti_dial(const char *service_name, const void *ziti_ctx, tunneler_io_context tnlr_io_ctx) {
    fprintf(stderr, "my_ziti_dial(%s)\n", service_name);
    ziti_context *zctx = (ziti_context *)ziti_ctx;

    ziti_io_context *ziti_io_ctx = malloc(sizeof(struct ziti_io_ctx_s));
    if (ziti_io_ctx == NULL) {
        fprintf(stderr, "failed to allocate io context\n");
        return NULL;
    }
    ziti_io_ctx->state = ZITI_CONNECTING;
    ziti_io_ctx->tnlr_io_ctx = tnlr_io_ctx;

    if (NF_conn_init(zctx->nf_ctx, &ziti_io_ctx->nf_conn, ziti_io_ctx) != ZITI_OK) {
        fprintf(stderr, "NF_conn_init failed\n");
        free(ziti_io_ctx);
        return NULL;
    }

    if (NF_dial(ziti_io_ctx->nf_conn, service_name, on_ziti_connect, on_ziti_data) != ZITI_OK) {
        fprintf(stderr, "NF_dial failed\n");
        free(ziti_io_ctx);
        return NULL;
    }

    return ziti_io_ctx;
}

/** called from tunneler SDK when intercepted client sends data */
ziti_conn_state my_ziti_write(const void *ziti_io_ctx, const void *data, int len) {
    struct ziti_io_ctx_s *_ziti_io_ctx = (struct ziti_io_ctx_s *)ziti_io_ctx;
//    fprintf(stderr, "my_ziti_write: state %d, %d bytes\n", _ziti_io_ctx->state, len);

    if (_ziti_io_ctx->state != ZITI_CONNECTED) {
        return _ziti_io_ctx->state;
    }

    if (NF_write(_ziti_io_ctx->nf_conn, (void *)data, len, NULL, NULL) == ZITI_OK) {
        return ZITI_CONNECTED;
    }

    return ZITI_FAILED;
}

/** callback from ziti SDK when a new service becomes available to our identity */
void on_service(nf_context nf_ctx, ziti_service *service, int status, void *tnlr_ctx) {
    printf("service_available: %s\n", service->name);

    ziti_context *ziti_ctx = malloc(sizeof(ziti_context));
    if (ziti_ctx == NULL) {
        fprintf(stderr, "failed to allocate dial context\n");
        return;
    }
    ziti_ctx->nf_ctx = nf_ctx;

    ziti_intercept intercept;
    if (status == ZITI_OK && (service->perm_flags & ZITI_CAN_DIAL)) {
        int rc = ziti_service_get_config(service, "ziti-tunneler-client.v1", &intercept, parse_ziti_intercept);
        if (rc == 0) {
            NF_tunneler_intercept_v1(tnlr_ctx, ziti_ctx, service->name, intercept.hostname, intercept.port);
            free(intercept.hostname);
        }
        printf("ziti_service_get_config rc: %d\n", rc);
    }
}

const char *cfg_types[] = { "ziti-tunneler-client.v1", "ziti-tunneler-server.v1", NULL };

int main(int argc, char *argv[]) {
    uv_loop_t *nf_loop = uv_default_loop();
    if (nf_loop == NULL) {
        fprintf(stderr, "failed to initialize default uv loop\n");
        return 1;
    }

    netif_driver tun;
    char tun_error[64];
#if __APPLE__ && __MACH__
    tun = utun_open(tun_error, sizeof(tun_error));
#endif

    if (tun == NULL) {
        fprintf(stderr, "failed to open network interface: %s\n", tun_error);
        return 1;
    }

    tunneler_sdk_options tunneler_opts = {
            .netif_driver = tun,
            .ziti_dial = my_ziti_dial,
            .ziti_close = my_ziti_close,
            .ziti_write = my_ziti_write
    };
    tunneler_context tnlr_ctx = NF_tunneler_init(&tunneler_opts, nf_loop);

    nf_options opts = {
            .config = "/Users/scarey/Downloads/localdev-0.13.json",
            .service_cb = on_service,
            .ctx = tnlr_ctx, /* this is passed to the service_cb */
            .refresh_interval = 10,
            .config_types = cfg_types,
    };

    if (NF_init_opts(&opts, nf_loop, NULL) != 0) {
        fprintf(stderr, "failed to initialize ziti\n");
        return 1;
    }

    if (uv_run(nf_loop, UV_RUN_DEFAULT) != 0) {
        fprintf(stderr, "failed to run event loop\n");
        exit(1);
    }

    free(tnlr_ctx);
    return 0;
}