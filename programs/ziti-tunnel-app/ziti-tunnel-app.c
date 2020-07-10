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

static void on_ziti_init(ziti_context ziti_ctx, int status, void *init_ctx);
static void on_service(ziti_context ziti_ctx, ziti_service *service, int status, void *tnlr_ctx);

const char *cfg_types[] = { "ziti-tunneler-client.v1", "ziti-tunneler-server.v1", NULL };
static ziti_options OPTS = {
        .config_types = cfg_types,
        .service_cb = on_service,
        .init_cb = on_ziti_init,
        .refresh_interval = 10, /* default refresh */
};

/** callback from ziti SDK when a new service becomes available to our identity */
void on_service(ziti_context ziti_ctx, ziti_service *service, int status, void *tnlr_ctx) {
    if (status == ZITI_OK && (service->perm_flags & ZITI_CAN_DIAL)) {
        ziti_intercept intercept;
        int rc = ziti_service_get_config(service, "ziti-tunneler-client.v1", &intercept, parse_ziti_intercept);
        if (rc == 0) {
            printf("service_available: %s\n", service->name);
            ziti_tunneler_intercept_v1(tnlr_ctx, ziti_ctx, service->id, service->name, intercept.hostname, intercept.port);
            free(intercept.hostname);
        }
        printf("ziti_service_get_config rc: %d\n", rc);
    } else if (status == ZITI_SERVICE_UNAVAILABLE) {
        printf("service unavailable: %s\n", service->name);
        ziti_tunneler_stop_intercepting(tnlr_ctx, service->id);
    }
}

static void on_ziti_init(ziti_context ziti_ctx, int status, void *init_ctx) {
    if (status != ZITI_OK) {
        fprintf(stderr, "failed to initialize ziti\n");
        exit(1);
    }
}

static int run_tunnel() {
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
            .ziti_write = ziti_sdk_c_write
    };
    tunneler_context tnlr_ctx = ziti_tunneler_init(&tunneler_opts, ziti_loop);

    OPTS.ctx = tnlr_ctx;

    if (ziti_init_opts(&OPTS, ziti_loop, NULL) != 0) {
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

#define COMMAND_LINE_IMPLEMENTATION
#include <commandline.h>
#include <getopt.h>

static CommandLine main_cmd;
static void usage() {
    commandline_print_usage(&main_cmd, stdout);
}

static struct option run_options[] = {
        { "config", required_argument, NULL, 'c' },
        { "debug", required_argument, NULL, 'd'},
        {"refresh", required_argument, NULL, 'r'},
};

static int run_opts(int argc, char *argv[]) {
    int c, option_index, errors = 0;
    optind = 0;

    while ((c = getopt_long(argc, argv, "c:d:r:",
                            run_options, &option_index)) != -1) {
        switch (c) {
            case 'c':
                printf("config = %s\n", optarg);
                OPTS.config = strdup(optarg);
                break;
            case 'd':
                setenv("ZITI_LOG", optarg, true);
                break;
            case 'r':
                OPTS.refresh_interval = strtol(optarg, NULL, 10);
                break;
            default: {
                fprintf(stderr, "Unknown option '%c'\n", c);
                errors++;
                break;
            }
        }
    }
    if (errors > 0) {
        commandline_help(stderr);
        exit(1);
    }
    return optind;
}

static void run(int argc, char *argv[]) {
    int rc = run_tunnel();
    exit(rc);
}

static int verbose_version;
static struct option version_options[] = {
        { "verbose", no_argument, NULL, 'v'},
};
static int version_opts(int argc, char *argv[]) {
    int c, option_index, errors = 0;
    optind = 0;

    while ((c = getopt_long(argc, argv, "v",
                            version_options, &option_index)) != -1) {
        switch (c) {
            case 'v':
                verbose_version = 1;
                break;
            default: {
                fprintf(stderr, "Unknown option '%c'\n", c);
                errors++;
                break;
            }
        }
    }
    if (errors > 0) {
        commandline_help(stderr);
        exit(1);
    }
    return optind;
}
static void version() {
    if (verbose_version) {
        printf("ziti-tunneler:\t%s\nziti-sdk:\t%s\n", ziti_tunneler_version(), ziti_get_version()->version);
    } else {
        printf("%s\n", ziti_tunneler_version());
    }
}

static CommandLine run_cmd = make_command("run", "run proxy", "run <service-name>:port", "start tunneler", run_opts, run);
static CommandLine ver_cmd = make_command("version", "show version", "version", NULL, version_opts, version);
static CommandLine help_cmd = make_command("help", "this message", NULL, NULL, NULL, usage);
static CommandLine *main_cmds[] = {
        &run_cmd,
        &ver_cmd,
        &help_cmd,
        NULL
};

#define GLOBAL_FLAGS "[--debug=level|-d[ddd]] [--config|-c=<path>] "
static CommandLine main_cmd = make_command_set(NULL,
                                        "Ziti Tunnel",
                                        GLOBAL_FLAGS
                                                "<command> [<args>]", "Ziti Tunnel",
                                        NULL, main_cmds);

int main(int argc, char *argv[]) {
    const char *name = strrchr(argv[0], '/');
    if (name == NULL) {
        name = argv[0];
    } else {
        name = name + 1;
    }
    main_cmd.name = name;
    commandline_run(&main_cmd, argc, argv);
    return 0;
}