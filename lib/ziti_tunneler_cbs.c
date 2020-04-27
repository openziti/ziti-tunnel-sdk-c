#include <stdio.h>
#include <nf/ziti_log.h>
#include "nf/ziti_tunneler_cbs.h"

void on_ziti_connect(nf_connection conn, int status) {
    ZITI_LOG(VERBOSE, "on_ziti_connect status: %d", status);
    ziti_io_context *ziti_io_ctx = NF_conn_data(conn);
    if (status == ZITI_OK) {
        NF_tunneler_dial_completed(&ziti_io_ctx->tnlr_io_ctx, ziti_io_ctx);
        ziti_io_ctx->state = ZITI_CONNECTED;
    } else {
        ziti_io_ctx->state = ZITI_FAILED;
        free(ziti_io_ctx);
    }
}

ssize_t on_ziti_data(nf_connection conn, uint8_t *data, ssize_t len) {
    ziti_io_context *ziti_io_ctx = NF_conn_data(conn);
    ZITI_LOG(TRACE, "got %zd bytes from ziti", len);
    if (ziti_io_ctx == NULL || ziti_io_ctx->tnlr_io_ctx == NULL) {
        ZITI_LOG(ERROR, "bad ziti_io_context");
        return len;
    }
    if (len > 0) {
        int accepted = NF_tunneler_write(&ziti_io_ctx->tnlr_io_ctx, data, len);
        if (accepted < 0) {
            ziti_sdk_c_close(ziti_io_ctx);
        }
        return accepted;
    } else {
        NF_tunneler_close(&ziti_io_ctx->tnlr_io_ctx);
    }
    return len;
}

/** called by tunneler SDK after a client connection is closed */
void ziti_sdk_c_close(void *ziti_io_ctx) {
    ziti_io_context *_ziti_io_ctx = ziti_io_ctx;
    if (_ziti_io_ctx->nf_conn != NULL) {
        NF_close(&_ziti_io_ctx->nf_conn);
    }
    //free(_ziti_io_ctx); // TODO don't know when it's OK to free this
}

/** called by tunneler SDK after a client connection is intercepted */
void * ziti_sdk_c_dial(const char *service_name, const void *ziti_ctx, tunneler_io_context tnlr_io_ctx) {
    ZITI_LOG(VERBOSE, "ziti_dial(%s)", service_name);
    ziti_context *zctx = (ziti_context *)ziti_ctx;

    ziti_io_context *ziti_io_ctx = malloc(sizeof(struct ziti_io_ctx_s));
    if (ziti_io_ctx == NULL) {
        ZITI_LOG(ERROR, "failed to allocate io context");
        return NULL;
    }
    ziti_io_ctx->state = ZITI_CONNECTING;
    ziti_io_ctx->tnlr_io_ctx = tnlr_io_ctx;

    if (NF_conn_init(zctx->nf_ctx, &ziti_io_ctx->nf_conn, ziti_io_ctx) != ZITI_OK) {
        ZITI_LOG(ERROR, "NF_conn_init failed");
        free(ziti_io_ctx);
        return NULL;
    }

    if (NF_dial(ziti_io_ctx->nf_conn, service_name, on_ziti_connect, on_ziti_data) != ZITI_OK) {
        ZITI_LOG(ERROR, "NF_dial failed");
        free(ziti_io_ctx);
        return NULL;
    }

    return ziti_io_ctx;
}

/** called by ziti SDK when data transfer initiated by NF_write completes */
static void on_ziti_write(nf_connection nf_conn, ssize_t len, void *ctx) {
    NF_tunneler_ack(ctx);
}

/** called from tunneler SDK when intercepted client sends data */
ziti_conn_state ziti_sdk_c_write(const void *ziti_io_ctx, void *write_ctx, const void *data, int len) {
    struct ziti_io_ctx_s *_ziti_io_ctx = (struct ziti_io_ctx_s *)ziti_io_ctx;
//    fprintf(stderr, "ziti_write: state %d, %d bytes\n", _ziti_io_ctx->state, len);

    if (_ziti_io_ctx->state != ZITI_CONNECTED) {
        return _ziti_io_ctx->state;
    }

    if (NF_write(_ziti_io_ctx->nf_conn, (void *)data, len, on_ziti_write, write_ctx) == ZITI_OK) {
        return ZITI_CONNECTED;
    }

    return ZITI_FAILED;
}