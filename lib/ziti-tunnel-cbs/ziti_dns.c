/*
Copyright 2019 Netfoundry, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <ziti/ziti_tunnel.h>
#include <ziti/ziti_log.h>
#include <ziti/ziti_dns.h>

typedef struct ziti_dns_client_s {} ziti_dns_client_t;

void* on_dns_client(const void *app_intercept_ctx, io_ctx_t *io);
int on_dns_close(void *ziti_io_ctx);
ssize_t on_dns_req(const void *ziti_io_ctx, void *write_ctx, const void *data, size_t len);

struct ziti_dns_s {

} ziti_dns;

int ziti_dns_setup(tunneler_context tnlr, const char *dns_addr, const char *dns_cidr) {

    intercept_ctx_t *dns_intercept = intercept_ctx_new(tnlr, "ziti:dns-resolver", &ziti_dns);
    intercept_ctx_add_address(dns_intercept, dns_addr);
    intercept_ctx_add_port_range(dns_intercept, 53, 53);
    intercept_ctx_add_protocol(dns_intercept, "udp");

    intercept_ctx_override_cbs(dns_intercept, on_dns_client, on_dns_req, on_dns_close, on_dns_close);

    ziti_tunneler_intercept(tnlr, dns_intercept);
    return 0;
}

void* on_dns_client(const void *app_intercept_ctx, io_ctx_t *io) {
    ZITI_LOG(INFO, "new DNS client");
    ziti_dns_client_t *clt = calloc(1, sizeof(ziti_dns_client_t));
    io->ziti_io = clt;
    ziti_tunneler_dial_completed(io, true);
    return clt;
}

ssize_t on_dns_req(const void *ziti_io_ctx, void *write_ctx, const void *data, size_t len) {
    ZITI_LOG(INFO, "new DNS req");

    return len;
}

int on_dns_close(void *dns_io_ctx) {
    ZITI_LOG(INFO, "DNS client close");
    free(dns_io_ctx);
}
