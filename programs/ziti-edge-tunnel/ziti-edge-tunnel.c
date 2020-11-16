#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "uv.h"
#include "ziti/ziti.h"
#include "ziti/ziti_tunnel.h"
#include "ziti/ziti_tunnel_cbs.h"
#include <ziti/ziti_log.h>

#if __APPLE__ && __MACH__
#include "netif_driver/darwin/utun.h"
#elif __linux__
#include "netif_driver/linux/tun.h"
#else
#error "please port this file to your operating system"
#endif

static void on_ziti_init(ziti_context ziti_ctx, int status, void *init_ctx) {
    if (status != ZITI_OK) {
        ZITI_LOG(ERROR, "failed to initialize ziti");
        exit(1);
    }
}

static void on_service(ziti_context ziti_ctx, ziti_service *service, int status, void *tnlr_ctx) {
    ziti_sdk_c_on_service(ziti_ctx, service, status, tnlr_ctx);
}

const char *cfg_types[] = { "ziti-tunneler-client.v1", "intercept.v1", "ziti-tunneler-server.v1", "host.v1", NULL };
static ziti_options OPTS = {
        .config_types = cfg_types,
        .service_cb = on_service,
        .init_cb = on_ziti_init,
        .refresh_interval = 10, /* default refresh */
};

extern dns_manager *get_dnsmasq_manager(const char* path);

static int run_tunnel(const char *ip_range, dns_manager *dns) {
    uv_loop_t *ziti_loop = uv_default_loop();
    if (ziti_loop == NULL) {
        ZITI_LOG(ERROR, "failed to initialize default uv loop");
        return 1;
    }

    netif_driver tun;
    char tun_error[64];
#if __APPLE__ && __MACH__
    tun = utun_open(tun_error, sizeof(tun_error), ip_range);
#elif __linux__
    tun = tun_open(tun_error, sizeof(tun_error), ip_range);
#endif

    if (tun == NULL) {
        ZITI_LOG(ERROR, "failed to open network interface: %s", tun_error);
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
    ziti_tunneler_set_dns(tnlr_ctx, dns);

    OPTS.ctx = tnlr_ctx;

    if (ziti_init_opts(&OPTS, ziti_loop, NULL) != 0) {
        ZITI_LOG(ERROR, "failed to initialize ziti");
        return 1;
    }

    if (uv_run(ziti_loop, UV_RUN_DEFAULT) != 0) {
        ZITI_LOG(ERROR, "failed to run event loop");
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
        { "refresh", required_argument, NULL, 'r'},
        { "ip", required_argument, NULL, 'i'},
        { "dns", optional_argument, NULL, 'n'},
};

static const char* ip_range = "100.64.0.0/10";
static const char* dns_impl = NULL;

static int run_opts(int argc, char *argv[]) {
    int c, option_index, errors = 0;
    optind = 0;

    while ((c = getopt_long(argc, argv, "c:d:r:i:n:",
                            run_options, &option_index)) != -1) {
        switch (c) {
            case 'c':
                OPTS.config = strdup(optarg);
                break;
            case 'd':
                setenv("ZITI_LOG", optarg, true);
                break;
            case 'r':
                OPTS.refresh_interval = strtol(optarg, NULL, 10);
                break;
            case 'i': // ip range
                ip_range = optarg;
                break;
            case 'n': // DNS manager implementation
                dns_impl = optarg;
                break;
            default: {
                ZITI_LOG(ERROR, "Unknown option '%c'", c);
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

    uint ip[4];
    int bits;
    int rc = sscanf(ip_range, "%d.%d.%d.%d/%d", &ip[0], &ip[1], &ip[2], &ip[3], &bits);
    if (rc != 5) {
        ZITI_LOG(ERROR, "Invalid IP range specification: n.n.n.n/m format is expected");
        exit(1);
    }

    uint32_t mask = 0;
    for (int i = 0; i < 4; i++) {
        mask <<= 8U;
        mask |= (ip[i] & 0xFFU);
    }

    dns_manager *dns = NULL;
    if (dns_impl == NULL) {
        // TODO internal DNS handling goes here(?)
        ZITI_LOG(WARN, "No DNS support specified; services won't be available by DNS names");
    } else if (strncmp("dnsmasq", dns_impl, strlen("dnsmasq")) == 0) {
        char *col = strchr(dns_impl, ':');
        if (col == NULL) {
            ZITI_LOG(ERROR, "DNS dnsmasq option should be `--dns=dnsmasq:<hosts-dir>");
            exit(1);
        }
        dns = get_dnsmasq_manager(col + 1);
    }

    ziti_tunneler_init_dns(mask, bits);
    rc = run_tunnel(ip_range, dns);
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

static ziti_enroll_opts enroll_opts;
static char* config_file;

static int parse_enroll_opts(int argc, char *argv[]) {
    static struct option opts[] = {
            {"jwt", required_argument, NULL, 'j'},
            {"identity", required_argument, NULL, 'i'},
            {"key", optional_argument, NULL, 'k'},
            {"cert", optional_argument, NULL, 'c'},
    };
    int c, option_index, errors = 0;
    optind = 0;

    while ((c = getopt_long(argc, argv, "j:i:k:c:",
                            opts, &option_index)) != -1) {
        switch (c) {
            case 'j':
                enroll_opts.jwt = realpath(optarg, NULL);
                break;
            case 'k':
                enroll_opts.enroll_key = realpath(optarg, NULL);
                break;
            case 'c':
                enroll_opts.enroll_cert = realpath(optarg, NULL);
                break;
            case 'i':
                config_file = optarg;
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

static void enroll_cb(ziti_config *cfg, int status, char *err, void *ctx) {
    if (status != ZITI_OK) {
        ZITI_LOG(ERROR, "enrollment failed: %s(%d)", err, status);
        exit(status);
    }

    FILE *f = ctx;

    char output_buf[16000];
    size_t len;
    json_from_ziti_config(cfg, output_buf, sizeof(output_buf), &len);

    if (fwrite(output_buf, 1, len, f) != len) {
        ZITI_LOG(ERROR, "failed to write config file");
        fclose(f);
        exit (-1);
    }

    fflush(f);
    fclose(f);
}

static void enroll(int argc, char *argv[]) {
    if (config_file == 0) {
        ZITI_LOG(ERROR, "output file option(-i|--identity) is required");
        exit(-1);
    }

    if (enroll_opts.jwt == NULL) {
        ZITI_LOG(ERROR, "JWT file option(-j|--jwt) is required");
        exit(-1);
    }

    FILE *outfile;
    if ((outfile = fopen(config_file, "wb")) == NULL) {
        ZITI_LOG(ERROR, "failed to open file %s: %s(%d)", config_file, strerror(errno), errno);
        exit(-1);

    }
    uv_loop_t *l = uv_loop_new();
    ziti_enroll(&enroll_opts, l, enroll_cb, outfile);

    uv_run(l, UV_RUN_DEFAULT);
}

static CommandLine enroll_cmd = make_command("enroll", "enroll Ziti identity",
        "enroll -j|--jwt <enrollment token> -i|--identity <identity> [-k|--key <private_key> [-c|--cert <certificate>]]", NULL,
        parse_enroll_opts, enroll);
static CommandLine run_cmd = make_command("run", "run Ziti tunnel", "run -i|--identity <identity>",
        "start tunneler", run_opts, run);
static CommandLine ver_cmd = make_command("version", "show version", "version", NULL, version_opts, version);
static CommandLine help_cmd = make_command("help", "this message", NULL, NULL, NULL, usage);
static CommandLine *main_cmds[] = {
        &enroll_cmd,
        &run_cmd,
        &ver_cmd,
        &help_cmd,
        NULL
};

#define GLOBAL_FLAGS "[--debug=level|-d[ddd]] [--config|-c=<path>] "
static CommandLine main_cmd = make_command_set(
        NULL,
        "Ziti Tunnel App",
        "<command> [<args>]", "Ziti Tunnel App",
        NULL, main_cmds);

int main(int argc, char *argv[]) {
    init_debug();
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