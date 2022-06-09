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
#include <stdlib.h>
#include <string.h>

#if _WIN32
#ifndef PATH_MAX
#define PATH_MAX MAX_PATH
#endif
#endif

static int apply_address(dns_manager *dns, const char *hostname, const char *ip);
static void remove_address(dns_manager *dns, const char *intercept_name);

struct dnsmasq_config {
    const char *mapping_dir;
};

static struct dnsmasq_config dnsmask_cfg;
dns_manager dnsmasq_manager = {
        .apply = apply_address,
        .remove = remove_address,
        .data = &dnsmask_cfg
};

static int apply_address(dns_manager *dns, const char *hostname, const char *ip) {
    ZITI_LOG(INFO, "Entered this function %s: %s", hostname, ip) ;
    char fname[PATH_MAX];
    struct dnsmasq_config *cfg = dns->data;
    sprintf(fname,  "%s/%s", cfg->mapping_dir, hostname);

    char entry[512];
    int c = snprintf(entry, sizeof(entry), "%s\t%s", ip, hostname);
    FILE *rec = fopen(fname, "wb");
    if (rec == NULL) {
        ZITI_LOG(ERROR, "failed to open %s: %s", fname, strerror(errno));
        return 1;
    }
    fwrite(entry, 1, c, rec);
    fflush(rec);
    fclose(rec);

    system("killall -HUP dnsmasq");
    ZITI_LOG(INFO, "successfully written the file %s", fname) ;
    return 0;
}

void remove_address(dns_manager *dns, const char *intercept_name) {
    ZITI_LOG(INFO, "Entered this function %s", intercept_name) ;
    char fname[PATH_MAX];
    struct dnsmasq_config *cfg = dns->data;
    sprintf(fname,  "%s/%s", cfg->mapping_dir, intercept_name);

    if (remove(fname) == 0)
      ZITI_LOG(DEBUG, "Deleted successfully");
    else
      ZITI_LOG(ERROR, "Unable to delete the file");
    
    return ;
}

dns_manager *get_dnsmasq_manager(const char* mapping_dir) {
    dnsmask_cfg.mapping_dir = mapping_dir;
    return &dnsmasq_manager;
}

