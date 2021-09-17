#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "uv.h"
#include "ziti/ziti.h"
#include "ziti/ziti_tunnel.h"
#include "ziti/ziti_tunnel_cbs.h"
#include <ziti/ziti_log.h>
#include <ziti/ziti_dns.h>
#include "model/events.h"
#include "instance.h"

#if __APPLE__ && __MACH__
#include "netif_driver/darwin/utun.h"
#elif __linux__
#include "netif_driver/linux/tun.h"
#elif _WIN32
#include "netif_driver/windows/tun.h"
#ifndef MAXPATHLEN
#define MAXPATHLEN _MAX_PATH
#endif

#define setenv(n,v,o) do {if(o || getenv(n) == NULL) _putenv_s(n,v); } while(0)
#endif



extern dns_manager *get_dnsmasq_manager(const char* path);

static int dns_fallback(const char *name, void *ctx, struct in_addr* addr);

static void send_message_to_tunnel();
static void send_events_message(void *message, size_t datalen);

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
static uv_pipe_t event_server;
static uv_pipe_t *event_conn;

// singleton
static const ziti_tunnel_ctrl *CMD_CTRL;
static long events_channels_count = 8;
static long current_events_channels = 0;

#define EVENT_ACTIONS(XX, ...) \
XX(added, __VA_ARGS__) \
XX(removed, __VA_ARGS__) \
XX(updated, __VA_ARGS__) \
XX(bulk, __VA_ARGS__) \
XX(error, __VA_ARGS__) \
XX(changed, __VA_ARGS__) \
XX(normal, __VA_ARGS__) \
XX(connected, __VA_ARGS__) \
XX(disconnected, __VA_ARGS__)

DECLARE_ENUM(event, EVENT_ACTIONS)
IMPL_ENUM(event, EVENT_ACTIONS)

#if _WIN32
static char sockfile[] = "\\\\.\\pipe\\ziti-edge-tunnel.sock";
static char eventsockfile[] = "\\\\.\\pipe\\ziti-edge-tunnel-event.sock";
#elif __unix__ || unix || ( __APPLE__ && __MACH__ )
static char sockfile[] = "/tmp/ziti-edge-tunnel.sock";
static char eventsockfile[] = "/tmp/ziti-edge-tunnel-event.sock";
#endif

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
            result->success, json_len, (int)json_len, json, result->data);

    if (result->data != NULL){
        free(result->data);
    }

    if (uv_is_active((const uv_handle_t *) &cmd_conn)) {
        uv_buf_t b = uv_buf_init(json, json_len);
        uv_write_t *wr = calloc(1, sizeof(uv_write_t));
        wr->data = b.base;
        uv_write(wr, (uv_stream_t *) &cmd_conn, &b, 1, on_cmd_write);
    }

}

static void on_cmd(uv_stream_t *s, ssize_t len, const uv_buf_t *b) {
    if (len < 0) {
        ZITI_LOG(WARN, "received from client - %s. Closing connection.", uv_err_name(len));
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

    uv_fs_t fs;
    uv_fs_unlink(l, &fs, sockfile, NULL);

#define CHECK_UV(op) do{ \
    int uv_rc = (op);    \
    if (uv_rc != 0) {    \
       ZITI_LOG(WARN, "failed to open IPC socket op=[%s] err=%d[%s]", #op, uv_rc, uv_strerror(uv_rc));\
       goto uv_err; \
    }                    \
    } while(0)


    CHECK_UV(uv_pipe_init(l, &cmd_server, 0));
    CHECK_UV(uv_pipe_bind(&cmd_server, sockfile));
    CHECK_UV(uv_pipe_chmod(&cmd_server, UV_WRITABLE | UV_READABLE));

    uv_unref((uv_handle_t *) &cmd_server);

    CHECK_UV(uv_listen((uv_stream_t *) &cmd_server, 0, on_cmd_client));

    return 0;

    uv_err:
    return -1;
}


static void on_events_client(uv_stream_t *s, int status) {
    if (current_events_channels < events_channels_count) {
        event_conn = malloc(sizeof(uv_pipe_t));
        uv_pipe_init(s->loop, event_conn, 0);
        uv_accept(s, (uv_stream_t *) event_conn);
        ZITI_LOG(DEBUG,"Received events connection request %d", ++current_events_channels);

        // send status message immediately
        tunnel_status_event tnl_sts_evt = {0};
        tnl_sts_evt.Op = strdup("status");
        tunnel_status *stat = get_tunnel_status();
        tnl_sts_evt.Status = stat;
        size_t json_len;
        char *json = tunnel_status_event_to_json(&tnl_sts_evt, MODEL_JSON_COMPACT, &json_len);
        send_events_message(json, json_len);
        tnl_sts_evt.Status = NULL;
        free_tunnel_status_event(&tnl_sts_evt);
    } else {
        ZITI_LOG(WARN, "Maximum events connection requests exceeded");
    }
}


void on_write_event(uv_write_t* req, int status) {
    if (status < 0) {
        ZITI_LOG(ERROR,"Could not sent events message. Write error %s\n", uv_err_name(status));
    } else {
        ZITI_LOG(DEBUG,"Events message is sent.");
    }
    if (req->data) {
        free(req->data);
    }
    free(req);
}

static void send_events_message(void *message, size_t data_len) {
    ZITI_LOG(INFO,"Events Message...%s", message);
    if (event_conn != NULL) {
        uv_buf_t buf = uv_buf_init(message, data_len);
        uv_write_t *wr = calloc(1, sizeof(uv_write_t));
        wr->data = buf.base;
        int err = uv_write(wr, event_conn, &buf, 1, on_write_event);
        if (err < 0){
            ZITI_LOG(ERROR,"Events client write operation failed, received error - %s", uv_err_name(err));
            if (err == UV_EPIPE) {
                if (current_events_channels > 0) {
                    ZITI_LOG(WARN,"Events client closed connection");
                    --current_events_channels;
                    uv_close((uv_handle_t *) event_conn, (uv_close_cb) free);
                    event_conn = NULL;
                    //remove from event conn list
                }
            }
        }
    }
}

static int start_event_socket(uv_loop_t *l) {

    if (uv_is_active((const uv_handle_t *) &event_server)) {
        return 0;
    }

    uv_fs_t fs;
    uv_fs_unlink(l, &fs, eventsockfile, NULL);

#define CHECK_UV(op) do{ \
    int uv_rc = (op);    \
    if (uv_rc != 0) {    \
       ZITI_LOG(WARN, "failed to open event socket op=[%s] err=%d[%s]", #op, uv_rc, uv_strerror(uv_rc));\
       goto uv_err; \
    }                    \
    } while(0)


    CHECK_UV(uv_pipe_init(l, &event_server, 0));
    CHECK_UV(uv_pipe_bind(&event_server, eventsockfile));
    CHECK_UV(uv_pipe_chmod(&event_server, UV_WRITABLE | UV_READABLE));

    uv_unref((uv_handle_t *) &event_server);

    CHECK_UV(uv_listen((uv_stream_t *) &event_server, 0, on_events_client));

    return 0;

    uv_err:
    return -1;
}

static void load_identities(uv_work_t *wr) {
    if (config_dir != NULL) {
        uv_fs_t fs;
        int rc = uv_fs_scandir(wr->loop, &fs, config_dir, 0, NULL);
        if (rc < 0) {
            ZITI_LOG(ERROR, "failed to scan dir[%s]: %d/%s", config_dir, rc, uv_strerror(rc));
            return;
        }

        uv_dirent_t file;
        while (uv_fs_scandir_next(&fs, &file) == 0) {
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

        CMD_CTRL->load_identity(NULL, inst->cfg, load_id_cb, inst);
    }
}

static void on_event(const base_event *ev) {
    switch (ev->event_type) {
        case TunnelEvent_ContextEvent: {
            const ziti_ctx_event *zev = (ziti_ctx_event *) ev;
            ZITI_LOG(INFO, "ztx[%s] status is %s", ev->identifier, zev->status);

            identity_event id_event = {0};
            id_event.Op = strdup("identity");
            id_event.Action = strdup(event_name(event_added));
            id_event.Id = get_tunnel_identity(ev->identifier);

            if (zev->code == ZITI_OK) {
                id_event.Id->Loaded = true;
                if (zev->name) {
                    id_event.Id->Name = strdup(zev->name);
                    id_event.Id->ControllerVersion = strdup(zev->version);
                    id_event.Id->Config.ZtAPI = strdup(zev->controller);
                }
                ZITI_LOG(DEBUG, "ztx[%s] controller connected", ev->identifier);
            }

            size_t json_len;
            char *json = identity_event_to_json(&id_event, MODEL_JSON_COMPACT, &json_len);
            send_events_message(json, json_len);
            id_event.Id = NULL;
            free_identity_event(&id_event);

            break;
        }

        case TunnelEvent_ServiceEvent: {
            const service_event *svc_ev = (service_event *) ev;
            ZITI_LOG(INFO, "ztx[%s] service event", ev->identifier);
            services_event svc_event = {
                .Op = strdup("bulkservice"),
                .Action = strdup(event_name(event_updated)),
                .Identifier = strdup(ev->identifier),
            };

            tunnel_identity *id = get_tunnel_identity(ev->identifier);
            ziti_service **zs;
            int idx = 0;
            if (svc_ev->removed_services != NULL) {
                svc_event.RemovedServices = calloc(sizeof(svc_ev->added_services) + 1, sizeof(tunnel_service *));
                for (zs = svc_ev->removed_services; *zs != NULL; zs++) {
                    tunnel_service *svc = get_tunnel_service(id, *zs);
                    svc_event.RemovedServices[idx++] = svc;
                }
            }

            idx = 0;
            if (svc_ev->added_services != NULL) {
                svc_event.AddedServices = calloc(sizeof(svc_ev->added_services) + 1, sizeof(tunnel_service *));
                for (zs = svc_ev->added_services; *zs != NULL; zs++) {
                    tunnel_service *svc = get_tunnel_service(id, *zs);
                    svc_event.AddedServices[idx++] = svc;
                }
            }

            if (svc_ev->removed_services != NULL || svc_ev->added_services != NULL) {
                add_or_remove_services_from_tunnel(id, svc_event.AddedServices, svc_event.RemovedServices);
            }

            size_t json_len;
            char *json = services_event_to_json(&svc_event, MODEL_JSON_COMPACT, &json_len);
            send_events_message(json, json_len);
            if (svc_event.AddedServices != NULL) {
                svc_event.AddedServices = NULL;
            }
            free_services_event(&svc_event);

            break;
        }

        case TunnelEvent_MFAEvent: {
            const mfa_event *mfa_ev = (mfa_event *) ev;
            ZITI_LOG(INFO, "ztx[%s] is requesting MFA code", ev->identifier);
            set_mfa_status(ev->identifier, true, true);
            identity_event id_event = {
                    .Op = strdup("identity"),
                    .Action = strdup(event_name(event_added)),
                    .Id = get_tunnel_identity(ev->identifier),
            };

            size_t json_len;
            char *json = identity_event_to_json(&id_event, MODEL_JSON_COMPACT, &json_len);
            send_events_message(json, json_len);
            id_event.Id = NULL;
            free_identity_event(&id_event);
            break;
        }

        case TunnelEvent_MFAStatusEvent:{
            const mfa_event *mfa_ev = (mfa_event *) ev;
            ZITI_LOG(INFO, "ztx[%s] MFA Status code : %d", ev->identifier, mfa_ev->code);

            mfa_status_event mfa_sts_event = {
                .Op = strdup("mfa"),
                .Action = strdup(mfa_ev->operation),
                .Identifier = strdup(mfa_ev->identifier)
            };

            if (mfa_ev->code == ZITI_OK) {
                // check for auth success
                set_mfa_status(ev->identifier, true, false);
                update_mfa_time(ev->identifier);
                mfa_sts_event.Successful = true;
            } else {
                mfa_sts_event.Successful = false;
                mfa_sts_event.Error = strdup(mfa_ev->status);
            }

            size_t json_len;
            char *json = mfa_status_event_to_json(&mfa_sts_event, MODEL_JSON_COMPACT, &json_len);
            send_events_message(json, json_len);
            free_mfa_status_event(&mfa_sts_event);
            break;
        }

        case TunnelEvent_Unknown:
        default:
            ZITI_LOG(WARN, "unhandled event received: %d", ev->event_type);
            break;
    }
}

static int run_tunnel(uv_loop_t *ziti_loop, uint32_t tun_ip, uint32_t dns_ip, const char *ip_range, dns_manager *dns) {
    netif_driver tun;
    char tun_error[64];
#if __APPLE__ && __MACH__
    tun = utun_open(tun_error, sizeof(tun_error), ip_range);
#elif __linux__
    tun = tun_open(ziti_loop, tun_ip, dns_ip, ip_range, tun_error, sizeof(tun_error));
#elif _WIN32
    tun = tun_open(ziti_loop, tun_ip, dns_ip, ip_range, tun_error, sizeof(tun_error));
#else
#error "ziti-edge-tunnel is not supported on this system"
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

    // generate tunnel status instance and save active state and start time
    tunnel_status *tnl_status = get_tunnel_status();
    tnl_status->Active = true;

    ziti_dns_setup(tunneler, ip4addr_ntoa(&dns_ip), ip_range);
    ziti_dns_set_fallback(ziti_loop, dns_fallback, NULL);

    CMD_CTRL = ziti_tunnel_init_cmd(ziti_loop, tunneler, on_event);

    uv_work_t *loader = calloc(1, sizeof(uv_work_t));
    uv_queue_work(ziti_loop, loader, load_identities, load_identities_complete);

    start_cmd_socket(ziti_loop);
    start_event_socket(ziti_loop);

    if (uv_run(ziti_loop, UV_RUN_DEFAULT) != 0) {
        ZITI_LOG(ERROR, "failed to run event loop");
        exit(1);
    }

    free(tunneler);
    uv_close((uv_handle_t *) &cmd_server, (uv_close_cb) free);
    uv_close((uv_handle_t *) &event_server, (uv_close_cb) free);
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

    uint32_t ip[4];
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

#if __unix__ || __unix
    // prevent termination when running under valgrind
    // client forcefully closing connection results in SIGPIPE
    // which causes valgrind to freak out
    signal(SIGPIPE, SIG_IGN);
#endif

    uv_loop_t *ziti_loop = uv_default_loop();
    ziti_log_init(ziti_loop, ZITI_LOG_DEFAULT_LEVEL, NULL);

    ziti_tunnel_set_log_level(ziti_log_level());
    ziti_tunnel_set_logger(ziti_logger);

    if (ziti_loop == NULL) {
        ZITI_LOG(ERROR, "failed to initialize default uv loop");
        exit(1);
    }

    dns_manager *dns = NULL;
    if (dns_impl && strncmp("dnsmasq", dns_impl, strlen("dnsmasq")) == 0) {
        char *col = strchr(dns_impl, ':');
        if (col == NULL) {
            ZITI_LOG(ERROR, "DNS dnsmasq option should be `--dns=dnsmasq:<hosts-dir>");
            exit(1);
        }
        dns = get_dnsmasq_manager(col + 1);
    } else if (dns_impl) {
        ZITI_LOG(ERROR, "DNS setting '%s' is not supported", dns_impl);
        exit(1);
    }

    rc = run_tunnel(ziti_loop, tun_ip, dns_ip, ip_range, dns);
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

#if _WIN32
#ifndef PATH_MAX
#define PATH_MAX MAX_PATH
#endif
#define realpath(rel, abs) _fullpath(abs, rel, PATH_MAX)
#endif

static int parse_enroll_opts(int argc, char *argv[]) {
    static struct option opts[] = {
            {"jwt", required_argument, NULL, 'j'},
            {"identity", required_argument, NULL, 'i'},
            {"key", optional_argument, NULL, 'k'},
            {"cert", optional_argument, NULL, 'c'},
            { "name", optional_argument, NULL, 'n'}
    };
    int c, option_index, errors = 0;
    optind = 0;

    while ((c = getopt_long(argc, argv, "j:i:k:c:n:",
                            opts, &option_index)) != -1) {
        switch (c) {
            case 'j':
                enroll_opts.jwt = optarg;
                break;
            case 'k':
                enroll_opts.enroll_key = realpath(optarg, NULL);
                break;
            case 'c':
                enroll_opts.enroll_cert = realpath(optarg, NULL);
                break;
            case 'n':
                enroll_opts.enroll_name = optarg;
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

static tunnel_comand *cmd;

static int dump_opts(int argc, char *argv[]) {
    static struct option opts[] = {
            {"identity", optional_argument, NULL, 'i'},
            {"dump_path", optional_argument, NULL, 'p'},
    };
    int c, option_index, errors = 0;
    optind = 0;

    tunnel_ziti_dump *dump_options = calloc(1, sizeof(tunnel_ziti_dump));
    cmd = calloc(1, sizeof(tunnel_comand));
    cmd->command = TunnelCommand_ZitiDump;

    while ((c = getopt_long(argc, argv, "i:p:",
                            opts, &option_index)) != -1) {
        switch (c) {
            case 'i':
                dump_options->identifier = optarg;
                break;
            case 'p':
                dump_options->dump_path = realpath(optarg, NULL);
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
    size_t json_len;
    cmd->data = tunnel_ziti_dump_to_json(dump_options, MODEL_JSON_COMPACT, &json_len);
    if (dump_options != NULL) {
        free_tunnel_ziti_dump(dump_options);
    }

    return optind;
}

static void on_response(uv_stream_t *s, ssize_t len, const uv_buf_t *b) {
    if (len > 0) {
        printf("received response <%.*s>\n", (int) len, b->base);
    } else {
        fprintf(stderr,"Read Response error %s\n", uv_err_name(len));
    }
    uv_read_stop(s);
    uv_close((uv_handle_t *)s, NULL);
}

void on_write(uv_write_t* req, int status) {
    if (status < 0) {
        fprintf(stderr,"Could not sent message to the tunnel. Write error %s\n", uv_err_name(status));
    } else {
        puts("Message sent to the tunnel.");
    }
    free(req);
}

void send_message_to_pipe(uv_connect_t *connect, void *message, size_t datalen) {
    printf("Message...%s\n", message);
    uv_write_t *req = (uv_write_t*) malloc(sizeof(uv_write_t));
    uv_buf_t buf = uv_buf_init(message, datalen);
    uv_write((uv_write_t*) req, connect->handle, &buf, 1,    on_write);
}

void on_connect(uv_connect_t* connect, int status){
    if (status < 0) {
        puts("failed to connect!");
    } else {
        puts("connected!");
        int res = uv_read_start((uv_stream_t *) connect->handle, cmd_alloc, on_response);
        if (res != 0) {
            printf("UV read error %s\n", uv_err_name(res));
        }

        size_t json_len;
        char* json = tunnel_comand_to_json(cmd, MODEL_JSON_COMPACT, &json_len);
        send_message_to_pipe(connect, json, json_len);
        free(json);
        free_tunnel_comand(cmd);
    }
}

static uv_loop_t* connect_and_send_cmd(char sockfile[],uv_connect_t* connect, uv_pipe_t* client_handle) {
    uv_loop_t* loop = uv_default_loop();

    int res = uv_pipe_init(loop, client_handle, 0);
    if (res != 0) {
        printf("UV client handle init failed %s\n", uv_err_name(res));
        return NULL;
    }

    uv_pipe_connect(connect, client_handle, sockfile, on_connect);

    return loop;
}

static void send_message_to_tunnel() {
    uv_pipe_t client_handle;
    uv_connect_t* connect = (uv_connect_t*)malloc(sizeof(uv_connect_t));

    uv_loop_t* loop = connect_and_send_cmd(sockfile, connect, &client_handle);

    if (loop == NULL) {
        printf("Cannot run UV loop, loop is null");
        return;
    }

    int res = uv_run(loop, UV_RUN_DEFAULT);
    if (res != 0) {
        printf("UV run error %s\n", uv_err_name(res));
    }
}

static void send_message_to_tunnel_fn(int argc, char *argv[]) {
    send_message_to_tunnel();
}

static int disable_identity_opts(int argc, char *argv[]) {
    static struct option opts[] = {
            {"identity", required_argument, NULL, 'i'},
    };
    int c, option_index, errors = 0;
    optind = 0;

    tunnel_disable_identity *disable_identity_options = calloc(1, sizeof(tunnel_disable_identity));
    cmd = calloc(1, sizeof(tunnel_comand));
    cmd->command = TunnelCommand_DisableIdentity;

    while ((c = getopt_long(argc, argv, "i:",
                            opts, &option_index)) != -1) {
        switch (c) {
            case 'i':
                disable_identity_options->path = realpath(optarg, NULL);
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
    size_t json_len;
    cmd->data = tunnel_disable_identity_to_json(disable_identity_options, MODEL_JSON_COMPACT, &json_len);

    return optind;
}

static int enable_identity_opts(int argc, char *argv[]) {
    static struct option opts[] = {
            {"identity", required_argument, NULL, 'i'},
    };
    int c, option_index, errors = 0;
    optind = 0;

    tunnel_load_identity *load_identity_options = calloc(1, sizeof(tunnel_load_identity));
    cmd = calloc(1, sizeof(tunnel_comand));
    cmd->command = TunnelCommand_LoadIdentity;

    while ((c = getopt_long(argc, argv, "i:",
                            opts, &option_index)) != -1) {
        switch (c) {
            case 'i':
                load_identity_options->path = realpath(optarg, NULL);
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
    size_t json_len;
    cmd->data = tunnel_load_identity_to_json(load_identity_options, MODEL_JSON_COMPACT, &json_len);

    return optind;
}

static int enable_mfa_opts(int argc, char *argv[]) {
    static struct option opts[] = {
            {"identity", required_argument, NULL, 'i'},
    };
    int c, option_index, errors = 0;
    optind = 0;

    tunnel_enable_mfa *enable_mfa_options = calloc(1, sizeof(tunnel_enable_mfa));
    cmd = calloc(1, sizeof(tunnel_comand));
    cmd->command = TunnelCommand_EnableMFA;

    while ((c = getopt_long(argc, argv, "i:",
                            opts, &option_index)) != -1) {
        switch (c) {
            case 'i':
                enable_mfa_options->identifier = optarg;
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
    size_t json_len;
    cmd->data = tunnel_enable_mfa_to_json(enable_mfa_options, MODEL_JSON_COMPACT, &json_len);

    return optind;
}

static int verify_mfa_opts(int argc, char *argv[]) {
    static struct option opts[] = {
            {"identity", required_argument, NULL, 'i'},
            {"code", required_argument, NULL, 'c'},
    };
    int c, option_index, errors = 0;
    optind = 0;

    tunnel_verify_mfa *verify_mfa_options = calloc(1, sizeof(tunnel_verify_mfa));
    cmd = calloc(1, sizeof(tunnel_comand));
    cmd->command = TunnelCommand_VerifyMFA;

    while ((c = getopt_long(argc, argv, "i:c:",
                            opts, &option_index)) != -1) {
        switch (c) {
            case 'i':
                verify_mfa_options->identifier = optarg;
                break;
            case 'c':
                verify_mfa_options->code = optarg;
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
    size_t json_len;
    cmd->data = tunnel_verify_mfa_to_json(verify_mfa_options, MODEL_JSON_COMPACT, &json_len);

    return optind;
}

static int remove_mfa_opts(int argc, char *argv[]) {
    static struct option opts[] = {
            {"identity", required_argument, NULL, 'i'},
            {"code", required_argument, NULL, 'c'},
    };
    int c, option_index, errors = 0;
    optind = 0;

    tunnel_remove_mfa *remove_mfa_options = calloc(1, sizeof(tunnel_remove_mfa));
    cmd = calloc(1, sizeof(tunnel_comand));
    cmd->command = TunnelCommand_RemoveMFA;

    while ((c = getopt_long(argc, argv, "i:c:",
                            opts, &option_index)) != -1) {
        switch (c) {
            case 'i':
                remove_mfa_options->identifier = optarg;
                break;
            case 'c':
                remove_mfa_options->code = optarg;
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
    size_t json_len;
    cmd->data = tunnel_remove_mfa_to_json(remove_mfa_options, MODEL_JSON_COMPACT, &json_len);

    return optind;
}

static int submit_mfa_opts(int argc, char *argv[]) {
    static struct option opts[] = {
            {"identity", required_argument, NULL, 'i'},
            {"code", required_argument, NULL, 'c'},
    };
    int c, option_index, errors = 0;
    optind = 0;

    tunnel_submit_mfa *submit_mfa_options = calloc(1, sizeof(tunnel_submit_mfa));
    cmd = calloc(1, sizeof(tunnel_comand));
    cmd->command = TunnelCommand_SubmitMFA;

    while ((c = getopt_long(argc, argv, "i:c:",
                            opts, &option_index)) != -1) {
        switch (c) {
            case 'i':
                submit_mfa_options->identifier = optarg;
                break;
            case 'c':
                submit_mfa_options->code = optarg;
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
    size_t json_len;
    cmd->data = tunnel_submit_mfa_to_json(submit_mfa_options, MODEL_JSON_COMPACT, &json_len);

    return optind;
}

static int generate_mfa_codes_opts(int argc, char *argv[]) {
    static struct option opts[] = {
            {"identity", required_argument, NULL, 'i'},
            {"code", required_argument, NULL, 'c'},
    };
    int c, option_index, errors = 0;
    optind = 0;

    tunnel_generate_mfa_codes *mfa_codes_options = calloc(1, sizeof(tunnel_generate_mfa_codes));
    cmd = calloc(1, sizeof(tunnel_comand));
    cmd->command = TunnelCommand_GenerateMFACodes;

    while ((c = getopt_long(argc, argv, "i:c:",
                            opts, &option_index)) != -1) {
        switch (c) {
            case 'i':
                mfa_codes_options->identifier = optarg;
                break;
            case 'c':
                mfa_codes_options->code = optarg;
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
    size_t json_len;
    cmd->data = tunnel_generate_mfa_codes_to_json(mfa_codes_options, MODEL_JSON_COMPACT, &json_len);

    return optind;
}

static int get_mfa_codes_opts(int argc, char *argv[]) {
    static struct option opts[] = {
            {"identity", required_argument, NULL, 'i'},
            {"code", required_argument, NULL, 'c'},
    };
    int c, option_index, errors = 0;
    optind = 0;

    tunnel_get_mfa_codes *get_mfa_codes_options = calloc(1, sizeof(tunnel_get_mfa_codes));
    cmd = calloc(1, sizeof(tunnel_comand));
    cmd->command = TunnelCommand_GetMFACodes;

    while ((c = getopt_long(argc, argv, "i:c:",
                            opts, &option_index)) != -1) {
        switch (c) {
            case 'i':
                get_mfa_codes_options->identifier = optarg;
                break;
            case 'c':
                get_mfa_codes_options->code = optarg;
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
    size_t json_len;
    cmd->data = tunnel_get_mfa_codes_to_json(get_mfa_codes_options, MODEL_JSON_COMPACT, &json_len);

    return optind;
}

static CommandLine enroll_cmd = make_command("enroll", "enroll Ziti identity",
        "-j|--jwt <enrollment token> -i|--identity <identity> [-k|--key <private_key> [-c|--cert <certificate>]] [-n|--name <name>]",
        "\t-j|--jwt\tenrollment token file\n"
        "\t-i|--identity\toutput identity file\n"
        "\t-k|--key\tprivate key for enrollment\n"
        "\t-c|--cert\tcertificate for enrollment\n"
        "\t-n|--name\tidentity name\n",
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
static CommandLine dump_cmd = make_command("dump", "dump the identities information", "[-i <identity>] [-p <dir>]",
                                           "\t-i|--identity\tdump identity info\n"
                                           "\t-p|--dump_path\tdump into path\n", dump_opts, send_message_to_tunnel_fn);
static CommandLine disable_id_cmd = make_command("disable", "disable the identities information", "[-i <identity>]",
                                           "\t-i|--identity\tidentity info that needs to be disabled\n", disable_identity_opts, send_message_to_tunnel_fn);
static CommandLine enable_id_cmd = make_command("enable", "enable the identities information", "[-i <identity>]",
                                                 "\t-i|--identity\tidentity info that needs to be enabled\n", enable_identity_opts, send_message_to_tunnel_fn);
static CommandLine enable_mfa_cmd = make_command("enable_mfa", "Enable MFA function fetches the totp url from the controller", "[-i <identity>]",
                                           "\t-i|--identity\tidentity info for enabling mfa\n", enable_mfa_opts, send_message_to_tunnel_fn);
static CommandLine verify_mfa_cmd = make_command("verify_mfa", "Verify the mfa login using the auth code while enabling mfa", "[-i <identity>] [-c <code>]",
                                                 "\t-i|--identity\tidentity info to verify mfa login\n"
                                                 "\t-c|--authcode\tauth code to verify mfa login\n", verify_mfa_opts, send_message_to_tunnel_fn);
static CommandLine remove_mfa_cmd = make_command("remove_mfa", "Removes MFA registration from the controller", "[-i <identity>] [-c <code>]",
                                                 "\t-i|--identity\tidentity info for removing mfa\n"
                                                 "\t-c|--authcode\tauth code to verify mfa login\n", remove_mfa_opts, send_message_to_tunnel_fn);
static CommandLine submit_mfa_cmd = make_command("submit_mfa", "Submit MFA code to authenticate to the controller", "[-i <identity>] [-c <code>]",
                                                 "\t-i|--identity\tidentity info for removing mfa\n"
                                                 "\t-c|--authcode\tauth code to authenticate mfa login\n", submit_mfa_opts, send_message_to_tunnel_fn);
static CommandLine generate_mfa_codes_cmd = make_command("generate_mfa_codes", "Generate MFA codes", "[-i <identity>] [-c <code>]",
                                                 "\t-i|--identity\tidentity info for generating mfa codes\n"
                                                 "\t-c|--authcode\tauth code to authenticate the request for generating mfa codes\n", generate_mfa_codes_opts, send_message_to_tunnel_fn);
static CommandLine get_mfa_codes_cmd = make_command("get_mfa_codes", "Get MFA codes", "[-i <identity>] [-c <code>]",
                                                         "\t-i|--identity\tidentity info for fetching mfa codes\n"
                                                         "\t-c|--authcode\tauth code to authenticate the request for fetching mfa codes\n", get_mfa_codes_opts, send_message_to_tunnel_fn);
static CommandLine ver_cmd = make_command("version", "show version", "[-v]", "\t-v\tshow verbose version information\n", version_opts, version);
static CommandLine help_cmd = make_command("help", "this message", NULL, NULL, NULL, usage);
static CommandLine *main_cmds[] = {
        &enroll_cmd,
        &run_cmd,
        &disable_id_cmd,
        &enable_id_cmd,
        &dump_cmd,
        &enable_mfa_cmd,
        &verify_mfa_cmd,
        &remove_mfa_cmd,
        &submit_mfa_cmd,
        &generate_mfa_codes_cmd,
        &get_mfa_codes_cmd,
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

// ******* TUNNEL EVENT BROADCAST MESSAGES
IMPL_MODEL(status_event, STATUS_EVENT)
IMPL_MODEL(action_event, ACTION_EVENT)
IMPL_MODEL(identity_event, IDENTITY_EVENT)
IMPL_MODEL(services_event, SERVICES_EVENT)
IMPL_MODEL(tunnel_status_event, TUNNEL_STATUS_EVENT)
IMPL_MODEL(mfa_status_event, MFA_STATUS_EVENT)
