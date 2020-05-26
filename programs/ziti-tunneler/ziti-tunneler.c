#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "uv.h"
#include "ziti/ziti.h"
#include "ziti/ziti_tunneler.h"
#include "ziti/ziti_tunneler_cbs.h"

#if __APPLE__ && __MACH__
#include "netif_driver/darwin/utun.h"
#elif __linux__
#include "netif_driver/linux/tun.h"
#else
#error "please port this file to your operating system"
#endif

/** callback from ziti SDK when a new service becomes available to our identity */
void on_service(ziti_context ziti_ctx, ziti_service *service, int status, void *tnlr_ctx) {
    if (status == ZITI_OK) {
        fprintf(stderr, "service %s available", service->name);
        if (service->perm_flags & ZITI_CAN_DIAL) {
            ziti_intercept v1_config;
            int get_config_rc;
            get_config_rc = ziti_service_get_config(service, "ziti-tunneler-client.v1", &v1_config, parse_ziti_intercept);
            if (get_config_rc == 0) {
                ziti_tunneler_intercept_v1(tnlr_ctx, ziti_ctx, service->name, v1_config.hostname, v1_config.port);
                free_ziti_intercept(&v1_config);
            } else {
                fprintf(stderr, "service %s lacks ziti-tunneler-client.v1 config; not intercepting", service->name);
            }
        }
        if (service->perm_flags & ZITI_CAN_BIND) {
            ziti_server_cfg_v1 v1_config;
            int get_config_rc;
            get_config_rc = ziti_service_get_config(service, "ziti-tunneler-server.v1", &v1_config, parse_ziti_server_cfg_v1);
            if (get_config_rc == 0) {
                ziti_tunneler_host_v1(tnlr_ctx, ziti_ctx, service->name, v1_config.protocol, v1_config.hostname, v1_config.port);
                free_ziti_server_cfg_v1(&v1_config);
            } else {
                fprintf(stderr, "service %s lacks ziti-tunneler-server.v1 config; not hosting", service->name);
            }
        }
    } else if (status == ZITI_SERVICE_UNAVAILABLE) {
        printf("service unavailable: %s\n", service->name);
        ziti_tunneler_stop_intercepting(tnlr_ctx, service->name);
    }
}

const char *cfg_types[] = { "ziti-tunneler-client.v1", "ziti-tunneler-server.v1", NULL };

static void on_ziti_init(ziti_context ziti_ctx, int status, void *init_ctx) {
    if (status != ZITI_OK) {
        fprintf(stderr, "failed to initialize ziti\n");
        exit(1);
    }
}

int main(int argc, char *argv[]) {
    uv_loop_t *ziti_loop = uv_default_loop();
    if (ziti_loop == NULL) {
        fprintf(stderr, "failed to initialize default uv loop\n");
        return 1;
    }

    netif_driver tun;
    char tun_error[64];
#if __APPLE__ && __MACH__
    tun = utun_open(tun_error, sizeof(tun_error));
#elif __linux__
    tun = tun_open(tun_error, sizeof(tun_error));
#endif

    if (tun == NULL) {
        fprintf(stderr, "failed to open network interface: %s\n", tun_error);
        return 1;
    }

    tunneler_sdk_options tunneler_opts = {
            .netif_driver = tun,
            .ziti_dial = ziti_sdk_c_dial,
            .ziti_close = ziti_sdk_c_close,
            .ziti_write = ziti_sdk_c_write,
            .ziti_host_v1 = ziti_sdk_c_host_v1
    };
    tunneler_context tnlr_ctx = ziti_tunneler_init(&tunneler_opts, ziti_loop);

    ziti_options opts = {
            .init_cb = on_ziti_init,
            .config = "/Users/scarey/Downloads/localdev-0.14.1.json",
            .service_cb = on_service,
            .ctx = tnlr_ctx, /* this is passed to the service_cb */
            .refresh_interval = 10,
            .config_types = cfg_types,
    };

    if (ziti_init_opts(&opts, ziti_loop, NULL) != 0) {
        fprintf(stderr, "failed to initialize ziti\n");
        return 1;
    }

    if (uv_run(ziti_loop, UV_RUN_DEFAULT) != 0) {
        fprintf(stderr, "failed to run event loop\n");
        exit(1);
    }

    free(tnlr_ctx);
    return 0;
}