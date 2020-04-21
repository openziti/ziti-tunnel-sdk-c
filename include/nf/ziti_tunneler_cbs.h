#ifndef ZITI_TUNNELER_SDK_ZITI_TUNNELER_CBS_H
#define ZITI_TUNNELER_SDK_ZITI_TUNNELER_CBS_H

#include "nf/ziti_tunneler.h"
#include "nf/ziti.h"

#ifdef __cplusplus
extern "C" {
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

/** called by tunneler SDK after a client connection is intercepted */
void *ziti_sdk_c_dial(const char *service_name, const void *ziti_ctx, tunneler_io_context tnlr_io_ctx);

/** called from tunneler SDK when intercepted client sends data */
ziti_conn_state ziti_sdk_c_write(const void *ziti_io_ctx, void *write_ctx, const void *data, int len);

/** called by tunneler SDK after a client connection is closed */
void ziti_sdk_c_close(void *ziti_io_ctx);

#ifdef __cplusplus
}
#endif

#endif //ZITI_TUNNELER_SDK_ZITI_TUNNELER_CBS_H