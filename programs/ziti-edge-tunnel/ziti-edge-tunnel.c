#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

extern dns_manager *get_dnsmasq_manager(const char* path);

struct cfg_instance_s {
    char *cfg;
    LIST_ENTRY(cfg_instance_s) _next;
};

// temporary list to pass info between parse and run
static LIST_HEAD(instance_list, cfg_instance_s) load_list;

static long refresh_interval = 10;

static char *config_dir = NULL;

static uv_pipe_t cmd_server;
static uv_pipe_t cmd_conn;

// singleton
static const ziti_tunnel_ctrl *CMD_CTRL;

static void cmd_alloc(uv_handle_t *s, size_t sugg, uv_buf_t *b) {
    b->base = malloc(sugg);
    b->len = sugg;
}

static void on_cmd_write(uv_write_t *wr, int len) {
    if (wr->data) {
        free(wr->data);
    }
    free(wr);
}

static void on_command_resp(const tunnel_result* result, void *ctx) {
    size_t json_len;
    char *json = tunnel_result_to_json(result, MODEL_JSON_COMPACT, &json_len);
    ZITI_LOG(INFO, "resp[%d,len=%zd] = %.*s",
            result->success, json_len, (int)json_len, json);

    if (uv_is_active((const uv_handle_t *) &cmd_conn)) {
        uv_buf_t b = uv_buf_init(json, json_len);
        uv_write_t *wr = calloc(1, sizeof(uv_write_t));
        wr->data = b.base;
        uv_write(wr, (uv_stream_t *) &cmd_conn, &b, 1, on_cmd_write);
    }
}

static void on_cmd(uv_stream_t *s, ssize_t len, const uv_buf_t *b) {
    if (len < 0) {
        uv_close((uv_handle_t *) s, NULL);
    } else {
        ZITI_LOG(INFO, "received cmd <%.*s>", (int) len, b->base);

        tunnel_comand cmd = {0};
        if (parse_tunnel_comand(&cmd, b->base, len) == 0) {
            CMD_CTRL->process(&cmd, on_command_resp, NULL);
        } else {
            tunnel_result resp = {
                    .success = false,
                    .error = "failed to parse command"
            };
            on_command_resp(&resp, NULL);
        }
        free_tunnel_comand(&cmd);
    }

    free(b->base);
}

static void on_cmd_client(uv_stream_t *s, int status) {
    // only allow a single client
    if (!uv_is_active((const uv_handle_t *) &cmd_conn)) {
        uv_pipe_init(s->loop, &cmd_conn, 0);
        uv_accept(s, (uv_stream_t *) &cmd_conn);
        uv_read_start((uv_stream_t *) &cmd_conn, cmd_alloc, on_cmd);
    } else {
        uv_pipe_t *tmp = malloc(sizeof(uv_pipe_t));
        uv_pipe_init(s->loop, tmp, 0);
        uv_accept(s, (uv_stream_t *) tmp);
        uv_close((uv_handle_t *) tmp, (uv_close_cb) free);
    }
}

static int start_cmd_socket(uv_loop_t *l) {

    if (uv_is_active((const uv_handle_t *) &cmd_server)) {
        return 0;
    }
    static char sockfile[] = "/tmp/ziti-edge-tunnel.sock";
    uv_fs_t fs;
    uv_fs_unlink(l, &fs, sockfile, NULL);

    uv_pipe_init(l, &cmd_server, 0);
    uv_pipe_bind(&cmd_server, sockfile);
    uv_pipe_chmod(&cmd_server, UV_WRITABLE | UV_READABLE);
    uv_unref((uv_handle_t *) &cmd_server);

    return uv_listen((uv_stream_t *) &cmd_server, 0, on_cmd_client);
}

static void load_identities(uv_work_t *wr) {
    if (config_dir != NULL) {
        uv_fs_t fs;
        int rc = uv_fs_scandir(wr->loop, &fs, config_dir, 0, NULL);
        if (rc < 0) {
            ZITI_LOG(ERROR, "failed to scan dir: %d/%s", rc, uv_strerror(rc));
        }

        uv_dirent_t file;
        while (uv_fs_scandir_next(&fs, &file) != UV_EOF) {
            ZITI_LOG(INFO, "file = %s %d", file.name, file.type);

            if (file.type == UV_DIRENT_FILE) {
                struct cfg_instance_s *inst = calloc(1, sizeof(struct cfg_instance_s));
                inst->cfg = malloc(MAXPATHLEN);
                snprintf(inst->cfg, MAXPATHLEN, "%s/%s", config_dir, file.name);
                LIST_INSERT_HEAD(&load_list, inst, _next);
            }
        }
    }
}

static void load_id_cb(const tunnel_result *res, void *ctx) {
    struct cfg_instance_s *inst = ctx;
    if (res->success) {
        ZITI_LOG(INFO, "identity[%s] loaded", inst->cfg);
    } else {
        ZITI_LOG(ERROR, "identity[%s] failed to load: %s", inst->cfg, res->error);
    }
    free((void*)inst->cfg);
    free(inst);
}

static void load_identities_complete(uv_work_t * wr, int status) {
    while(!LIST_EMPTY(&load_list)) {
        struct cfg_instance_s *inst = LIST_FIRST(&load_list);
        LIST_REMOVE(inst, _next);

        CMD_CTRL->load_identity(inst->cfg, load_id_cb, inst);
    }
}

static int run_tunnel(uv_loop_t *ziti_loop, uint32_t tun_ip, const char *ip_range, dns_manager *dns) {
    netif_driver tun;
    char tun_error[64];
#if __APPLE__ && __MACH__
    tun = utun_open(tun_error, sizeof(tun_error), ip_range);
#elif __linux__
    tun = tun_open(ziti_loop, tun_ip, dns->dns_ip, ip_range, tun_error, sizeof(tun_error));
#endif

    if (tun == NULL) {
        ZITI_LOG(ERROR, "failed to open network interface: %s", tun_error);
        return 1;
    }

    tunneler_sdk_options tunneler_opts = {
            .netif_driver = tun,
            .ziti_dial = ziti_sdk_c_dial,
            .ziti_close = ziti_sdk_c_close,
            .ziti_close_write = ziti_sdk_c_close_write,
            .ziti_write = ziti_sdk_c_write,
            .ziti_host = ziti_sdk_c_host

    };

    tunneler_context tunneler = ziti_tunneler_init(&tunneler_opts, ziti_loop);
    ziti_tunneler_set_dns(tunneler, dns);

    CMD_CTRL = ziti_tunnel_init_cmd(ziti_loop, tunneler, NULL);

    uv_work_t *loader = calloc(1, sizeof(uv_work_t));
    uv_queue_work(ziti_loop, loader, load_identities, load_identities_complete);

    start_cmd_socket(ziti_loop);

    if (uv_run(ziti_loop, UV_RUN_DEFAULT) != 0) {
        ZITI_LOG(ERROR, "failed to run event loop");
        exit(1);
    }

    free(tunneler);
    return 0;
}

#define COMMAND_LINE_IMPLEMENTATION
#include <commandline.h>
#include <getopt.h>

static CommandLine main_cmd;
static void usage(int argc, char *argv[]) {
    if (argc == 0) {
        commandline_print_usage(&main_cmd, stdout);
        return;
    }

    if (strcmp(argv[0], "help") == 0) {
        printf("seriously? you need help\n");
        return;
    }
    char *help_args[] = {
            "ziti-edge-tunnel",
            argv[0],
            "-h"
    };
    commandline_run(&main_cmd, 3, help_args);
}

static struct option run_options[] = {
        { "identity", required_argument, NULL, 'i' },
        { "identity-dir", required_argument, NULL, 'I'},
        { "verbose", required_argument, NULL, 'v'},
        { "refresh", required_argument, NULL, 'r'},
        { "dns-ip-range", required_argument, NULL, 'd'},
        { "dns", required_argument, NULL, 'n'},
};

static const char* ip_range = "100.64.0.0/10";
static const char* dns_impl = NULL;

static int run_opts(int argc, char *argv[]) {
    ziti_set_app_info(main_cmd.name, ziti_tunneler_version());

    int c, option_index, errors = 0;
    optind = 0;

    while ((c = getopt_long(argc, argv, "i:I:v:r:d:n:",
                            run_options, &option_index)) != -1) {
        switch (c) {
            case 'i': {
                struct cfg_instance_s *inst = calloc(1, sizeof(struct cfg_instance_s));
                inst->cfg = strdup(optarg);
                LIST_INSERT_HEAD(&load_list, inst, _next);
                break;
            }
            case 'I':
                config_dir = optarg;
                break;
            case 'v':
                setenv("ZITI_LOG", optarg, true);
                break;
            case 'r':
                refresh_interval = strtol(optarg, NULL, 10);
                break;
            case 'd': // ip range
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

static int dns_fallback(const char *name, void *ctx, struct in_addr* addr) {
    return 3; // NXDOMAIN
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

    uint32_t tun_ip = htonl(mask | 0x1);
    uint32_t dns_ip = htonl(mask | 0x2);

    uv_loop_t *ziti_loop = uv_default_loop();
    ziti_log_init(ziti_loop, ZITI_LOG_DEFAULT_LEVEL, NULL);

    ziti_tunnel_set_log_level(ziti_log_level());
    ziti_tunnel_set_logger(ziti_logger);

    if (ziti_loop == NULL) {
        ZITI_LOG(ERROR, "failed to initialize default uv loop");
        exit(1);
    }

    dns_manager *dns = NULL;
    if (dns_impl == NULL || strcmp(dns_impl, "internal") == 0) {
        ZITI_LOG(INFO, "setting up internal DNS");
        dns = get_tunneler_dns(ziti_loop, dns_ip, dns_fallback, NULL);
    } else if (strncmp("dnsmasq", dns_impl, strlen("dnsmasq")) == 0) {
        char *col = strchr(dns_impl, ':');
        if (col == NULL) {
            ZITI_LOG(ERROR, "DNS dnsmasq option should be `--dns=dnsmasq:<hosts-dir>");
            exit(1);
        }
        dns = get_dnsmasq_manager(col + 1);
    } else {
        ZITI_LOG(ERROR, "DNS setting '%s' is not supported", dns_impl);
        exit(1);
    }

    ziti_tunneler_init_dns(mask, bits);

    rc = run_tunnel(ziti_loop, tun_ip, ip_range, dns);
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

    size_t len;
    char *cfg_json = ziti_config_to_json(cfg, 0, &len);

    if (fwrite(cfg_json, 1, len, f) != len) {
        ZITI_LOG(ERROR, "failed to write config file");
        fclose(f);
        exit (-1);
    }

    free(cfg_json);
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
        "-j|--jwt <enrollment token> -i|--identity <identity> [-k|--key <private_key> [-c|--cert <certificate>]]",
        "\t-j|--jwt\tenrollment token file\n"
        "\t-i|--identity\toutput identity file\n"
        "\t-k|--key\tprivate key for enrollment\n"
        "\t-c|--cert\tcertificate for enrollment\n",
        parse_enroll_opts, enroll);
static CommandLine run_cmd = make_command("run", "run Ziti tunnel (required superuser access)",
                                          "-i <id.file> [-r N] [-v N] [-d|--dns-ip-range N.N.N.N/n] [-n|--dns <internal|dnsmasq=<dnsmasq hosts dir>>]",
                                          "\t-i|--identity <identity>\trun with provided identity file (required)\n"
                                          "\t-I|--identity-dir <dir>\tload identities from provided directory\n"
                                          "\t-v|--verbose N\tset log level, higher level -- more verbose (default 3)\n"
                                          "\t-r|--refresh N\tset service polling interval in seconds (default 10)\n"
                                          "\t-d|--dns-ip-range <ip range>\tspecify CIDR block in which service DNS names"
                                          " are assigned in N.N.N.N/n format (default 100.64.0.0/10)\n"
                                          "\t-n|--dns <internal|dnsmasq=<dnsmasq opts>> DNS configuration setting (default internal)\n",
        run_opts, run);
static CommandLine ver_cmd = make_command("version", "show version", "[-v]", "\t-v\tshow verbose version information\n", version_opts, version);
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
        "<command> [<args>]", "to get help for specific command run 'ziti-edge-tunnel help <command>' "
                              "or 'ziti-edge-tunnel <command> -h'",
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