#include "ziti-tunneler-cbs.h"

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
    if (len > 0) {
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

static void on_ziti_write(nf_connection nf_conn, ssize_t len, void *ctx) {
// ctx wants to be... tunneler_io_context?
}

/** called from tunneler SDK when intercepted client sends data */
ziti_conn_state my_ziti_write(const void *ziti_io_ctx, const void *data, int len) {
    struct ziti_io_ctx_s *_ziti_io_ctx = (struct ziti_io_ctx_s *)ziti_io_ctx;
//    fprintf(stderr, "my_ziti_write: state %d, %d bytes\n", _ziti_io_ctx->state, len);

    if (_ziti_io_ctx->state != ZITI_CONNECTED) {
        return _ziti_io_ctx->state;
    }

    if (NF_write(_ziti_io_ctx->nf_conn, (void *)data, len, on_ziti_write, NULL) == ZITI_OK) {
        return ZITI_CONNECTED;
    }

    return ZITI_FAILED;
}