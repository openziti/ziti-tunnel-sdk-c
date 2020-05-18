#ifndef ZITI_TUNNELER_SDK_ZITI_TUNNELER_CBS_H
#define ZITI_TUNNELER_SDK_ZITI_TUNNELER_CBS_H

#include "nf/ziti_tunneler.h"
#include "ziti/ziti.h"

#ifdef __cplusplus
extern "C" {
#endif

/** context passed through the tunneler SDK for network i/o */
typedef struct ziti_io_ctx_s {
    ziti_connection      ziti_conn;
    tunneler_io_context  tnlr_io_ctx;
} ziti_io_context;

/** called by tunneler SDK after a client connection is intercepted */
void *ziti_sdk_c_dial(const intercept_ctx_t *intercept_ctx, tunneler_io_context tnlr_io_ctx);

/** called from tunneler SDK when intercepted client sends data */
ssize_t ziti_sdk_c_write(const void *ziti_io_ctx, void *write_ctx, const void *data, size_t len);

/** called by tunneler SDK after a client connection is closed */
void ziti_sdk_c_close(void *ziti_io_ctx);

#ifdef __cplusplus
}
#endif

#endif //ZITI_TUNNELER_SDK_ZITI_TUNNELER_CBS_H