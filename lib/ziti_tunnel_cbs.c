#if _WIN32
// _WIN32_WINNT needs to be declared and needs to be > 0x600 in order for 
// some constants used below to be declared
#define _WIN32_WINNT  _WIN32_WINNT_WIN6
 // Windows Server 2008
#include <ws2tcpip.h>
#endif

#include <stdio.h>
#include <ziti/ziti_log.h>
#include <memory.h>
#include "ziti/ziti_tunnel_cbs.h"

static void ziti_conn_close_cb(ziti_connection zc);

static void on_ziti_connect(ziti_connection conn, int status) {
    ZITI_LOG(VERBOSE, "on_ziti_connect status: %d", status);
    struct io_ctx_s *io = ziti_conn_data(conn);
    if (io == NULL) {
        ZITI_LOG(WARN, "null io. underlay connection possibly leaked. ziti_conn[%p] status[%d]", conn, status);
        ziti_close(conn, NULL);
        return;
    }
    if (status == ZITI_OK) {
        ziti_tunneler_dial_completed(io, true);
    } else {
        ZITI_LOG(ERROR, "ziti dial failed: %s", ziti_errorstr(status));
        ziti_close(conn, ziti_conn_close_cb);
    }
}

/** called by ziti SDK when ziti service has data for the client */
static ssize_t on_ziti_data(ziti_connection conn, uint8_t *data, ssize_t len) {
    struct io_ctx_s *io = ziti_conn_data(conn);
    ZITI_LOG(TRACE, "got %zd bytes from ziti", len);
    if (io == NULL) {
        ZITI_LOG(WARN, "null io. underlay connection possibly leaked. ziti_conn[%p] len[%zd]", conn, len);
        ziti_close(conn, NULL);
        return UV_ECONNABORTED;
    }
    ziti_io_context *ziti_io_ctx = io->ziti_io;
    if (len > 0) {
        int accepted = ziti_tunneler_write(io->tnlr_io, data, len);
        if (accepted < 0) {
            ZITI_LOG(ERROR, "failed to write to client");
            ziti_sdk_c_close(io->ziti_io);
        }
        return accepted;
    } else if (len == ZITI_EOF) {
        ZITI_LOG(DEBUG, "ziti connection sent EOF (ziti_eof=%d, tnlr_eof=%d)", ziti_io_ctx->ziti_eof, ziti_io_ctx->tnlr_eof);
        ziti_io_ctx->ziti_eof = true; /* no more data will come from this connection */
        if (ziti_io_ctx->tnlr_eof) /* both sides are done sending now, so close both */ {
            ziti_close(conn, ziti_conn_close_cb);
        } else {
            // this ziti conn can still receive but it will not send any more, so
            // we will not write to the client any more. send FIN to the client.
            // eventually the client will send FIN and the tsdk will call ziti_sdk_c_close_write.
            ziti_tunneler_close_write(io->tnlr_io);
        }
    } else if (len < 0) {
        ZITI_LOG(DEBUG, "ziti connection is closed due to [%zd](%s)", len, ziti_errorstr(len));
        ziti_close(conn, ziti_conn_close_cb);
    }
    return len;
}

/** called by tunneler SDK after a client connection is closed */
int ziti_sdk_c_close(void *io_ctx) {
    ziti_io_context *ziti_io_ctx = io_ctx;
    ZITI_LOG(DEBUG, "closing ziti_conn tnlr_eof=%d, ziti_eof=%d", ziti_io_ctx->tnlr_eof, ziti_io_ctx->ziti_eof);
    ziti_close(ziti_io_ctx->ziti_conn, ziti_conn_close_cb);
    return 1; // todo how is return value used?
}

/** called by tunneler SDK after a client sends FIN */
int ziti_sdk_c_close_write(void *io_ctx) {
    ziti_io_context *ziti_io_ctx = io_ctx;
    ZITI_LOG(DEBUG, "closing ziti_conn tnlr_eof=%d, ziti_eof=%d", ziti_io_ctx->tnlr_eof, ziti_io_ctx->ziti_eof);
    ziti_io_ctx->tnlr_eof = true;
    if (ziti_io_ctx->ziti_eof) { // both sides are now closed
        ZITI_LOG(DEBUG, "closing ziti_conn tnlr_eof=%d, ziti_eof=%d", ziti_io_ctx->tnlr_eof, ziti_io_ctx->ziti_eof);
        ziti_close(ziti_io_ctx->ziti_conn, ziti_conn_close_cb);
        return 1;
    }

    ZITI_LOG(DEBUG, "closing ziti_conn tnlr_eof=%d, ziti_eof=%d", ziti_io_ctx->tnlr_eof, ziti_io_ctx->ziti_eof);
    ziti_close_write(ziti_io_ctx->ziti_conn);
    return 0;
}

/** called by tunneler SDK after a client connection is intercepted */
void * ziti_sdk_c_dial(const intercept_ctx_t *intercept_ctx, struct io_ctx_s *io) {
    ZITI_LOG(VERBOSE, "ziti_dial(name=%s,id=%s)", intercept_ctx->service_name, intercept_ctx->service_id);

    ziti_io_context *ziti_io_ctx = malloc(sizeof(struct ziti_io_ctx_s));
    if (ziti_io_ctx == NULL) {
        ZITI_LOG(ERROR, "failed to allocate io context");
        return NULL;
    }
    io->ziti_io = ziti_io_ctx;

    ziti_context ziti_ctx = (ziti_context)intercept_ctx->ziti_ctx;
    if (ziti_conn_init(ziti_ctx, &ziti_io_ctx->ziti_conn, io) != ZITI_OK) {
        ZITI_LOG(ERROR, "ziti_conn_init failed");
        free(ziti_io_ctx);
        return NULL;
    }

    if (ziti_dial(ziti_io_ctx->ziti_conn, intercept_ctx->service_name, on_ziti_connect, on_ziti_data) != ZITI_OK) {
        ZITI_LOG(ERROR, "ziti_dial failed");
        free(ziti_io_ctx);
        return NULL;
    }
    ziti_io_ctx->ziti_eof = false;
    ziti_io_ctx->tnlr_eof = false;

    return ziti_io_ctx;
}

/** called by ziti SDK when data transfer initiated by ziti_write completes */
static void on_ziti_write(ziti_connection ziti_conn, ssize_t len, void *ctx) {
    if (len > 0) {
        ziti_tunneler_ack(ctx);
    }
    free(ctx);
}

/** called from tunneler SDK when intercepted client sends data */
ssize_t ziti_sdk_c_write(const void *ziti_io_ctx, void *write_ctx, const void *data, size_t len) {
    struct ziti_io_ctx_s *_ziti_io_ctx = (struct ziti_io_ctx_s *)ziti_io_ctx;
    int zs = ziti_write(_ziti_io_ctx->ziti_conn, (void *)data, len, on_ziti_write, write_ctx);
    if (zs != ZITI_OK) {
        ZITI_LOG(ERROR, "ziti_write(ziti_conn[%p]) failed: %s", _ziti_io_ctx->ziti_conn, ziti_errorstr(zs));
        on_ziti_write(_ziti_io_ctx->ziti_conn, len, write_ctx);
        ziti_close(_ziti_io_ctx->ziti_conn, ziti_conn_close_cb);
    }
    return zs;
}

/** called by ziti sdk after ziti_close completes */
static void ziti_conn_close_cb(ziti_connection zc) {
    ZITI_LOG(TRACE, "ziti_conn[%p] is closed", zc);
    struct io_ctx_s *io = ziti_conn_data(zc);
    if (io == NULL) {
        ZITI_LOG(WARN, "null io. underlay connection possibly leaked. ziti_conn[%p]", zc);
        return;
    }
    if (io->ziti_io) {
        free(io->ziti_io);
    }
    ziti_tunneler_close(io->tnlr_io);
    free(io);
    ziti_conn_set_data(zc, NULL);
    ZITI_LOG(VERBOSE, "nulled data for ziti_conn[%p]");
}