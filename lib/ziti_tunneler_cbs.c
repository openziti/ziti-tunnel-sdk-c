#include <stdio.h>
#include <ziti/ziti_log.h>
#include "ziti/ziti_tunneler_cbs.h"

void on_ziti_connect(ziti_connection conn, int status) {
    ZITI_LOG(VERBOSE, "on_ziti_connect status: %d", status);
    ziti_io_context *ziti_io_ctx = ziti_conn_data(conn);
    if (status == ZITI_OK) {
        ziti_tunneler_dial_completed(&ziti_io_ctx->tnlr_io_ctx, ziti_io_ctx, status == ZITI_OK);
    } else {
        free(ziti_io_ctx);
    }
}

ssize_t on_ziti_data(ziti_connection conn, uint8_t *data, ssize_t len) {
    ziti_io_context *ziti_io_ctx = ziti_conn_data(conn);
    ZITI_LOG(TRACE, "got %zd bytes from ziti", len);
    if (ziti_io_ctx == NULL || ziti_io_ctx->tnlr_io_ctx == NULL) {
        ZITI_LOG(ERROR, "bad ziti_io_context");
        return len;
    }
    if (len > 0) {
        int accepted = ziti_tunneler_write(&ziti_io_ctx->tnlr_io_ctx, data, len);
        if (accepted < 0) {
            ziti_sdk_c_close(ziti_io_ctx);
        }
        return accepted;
    } else {
        ziti_tunneler_close(&ziti_io_ctx->tnlr_io_ctx);
    }
    return len;
}

/** called by tunneler SDK after a client connection is closed */
void ziti_sdk_c_close(void *ziti_io_ctx) {
    ziti_io_context *_ziti_io_ctx = ziti_io_ctx;
    if (_ziti_io_ctx->ziti_conn != NULL) {
        ziti_close(&_ziti_io_ctx->ziti_conn);
    }
    //free(_ziti_io_ctx); // TODO don't know when it's OK to free this
}

/** called by tunneler SDK after a client connection is intercepted */
void * ziti_sdk_c_dial(const intercept_ctx_t *intercept_ctx, tunneler_io_context tnlr_io_ctx) {
    if (intercept_ctx == NULL) {
        ZITI_LOG(WARN, "null intercept_ctx");
        return NULL;
    }
    ZITI_LOG(VERBOSE, "ziti_dial(name=%s,id=%s)", intercept_ctx->service_name, intercept_ctx->service_id);

    ziti_io_context *ziti_io_ctx = malloc(sizeof(struct ziti_io_ctx_s));
    if (ziti_io_ctx == NULL) {
        ZITI_LOG(ERROR, "failed to allocate io context");
        return NULL;
    }
    ziti_io_ctx->tnlr_io_ctx = tnlr_io_ctx;

    ziti_context ziti_ctx = (ziti_context)intercept_ctx->ziti_ctx;
    if (ziti_conn_init(ziti_ctx, &ziti_io_ctx->ziti_conn, ziti_io_ctx) != ZITI_OK) {
        ZITI_LOG(ERROR, "ziti_conn_init failed");
        free(ziti_io_ctx);
        return NULL;
    }

    if (ziti_dial(ziti_io_ctx->ziti_conn, intercept_ctx->service_name, on_ziti_connect, on_ziti_data) != ZITI_OK) {
        ZITI_LOG(ERROR, "ziti_dial failed");
        free(ziti_io_ctx);
        return NULL;
    }

    return ziti_io_ctx;
}

/** called by ziti SDK when data transfer initiated by ziti_write completes */
static void on_ziti_write(ziti_connection ziti_conn, ssize_t len, void *ctx) {
    ziti_tunneler_ack(ctx);
}

/** called from tunneler SDK when intercepted client sends data */
ssize_t ziti_sdk_c_write(const void *ziti_io_ctx, void *write_ctx, const void *data, size_t len) {
    struct ziti_io_ctx_s *_ziti_io_ctx = (struct ziti_io_ctx_s *)ziti_io_ctx;
    return ziti_write(_ziti_io_ctx->ziti_conn, (void *)data, len, on_ziti_write, write_ctx);
}