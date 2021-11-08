/*
 Copyright 2019-2021 NetFoundry Inc.

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
#if _WIN32

#include <ziti/ziti_log.h>
#include <model/dtos.h>
#include "ziti/ziti_tunnel.h"
#include "windows/windows-scripts.h"

#define MAX_BUCKET_SIZE 500

static char* const namespace_template = "%s@{n='%s';}";
static char* const exe_name = "ziti-tunnel";

struct hostname_s {
    char *hostname;
    LIST_ENTRY(hostname_s) _next;
};

void chunked_add_nrpt_rules(LIST_HEAD(hostnames_list, hostname_s) *hostnames, char* tun_ip) {
    char* result = calloc(MAX_POWERSHELL_SCRIPT_LEN, sizeof(char));
    size_t buf_len = sprintf(result, "$Namespaces = @(");
    size_t copied = buf_len;
    int domains_size = 0;

    while(!LIST_EMPTY(hostnames)) {
        struct hostname_s *hostname = LIST_FIRST(hostnames);
        buf_len = sprintf(result + copied, namespace_template, "\n", hostname->hostname);
        copied += buf_len;
        domains_size++;
        LIST_REMOVE(hostname, _next);
        free(hostname->hostname);
        free(hostname);
    }
    buf_len = sprintf(result + copied, "%s\n\n", ")");
    copied += buf_len;

    buf_len = sprintf(result + copied, "ForEach ($Namespace in $Namespaces) {\n");
    copied += buf_len;
    buf_len = sprintf(result + copied, "$ns=$Namespace['n']\n");
    copied += buf_len;
    buf_len = sprintf(result + copied, "$Rule = @{Namespace=${ns}; NameServers=@('%s'); Comment='Added by %s'; DisplayName='%s:'+${ns}; }\n", tun_ip, exe_name, exe_name);
    copied += buf_len;
    buf_len = sprintf(result + copied, "Add-DnsClientNrptRule @Rule\n");
    copied += buf_len;
    buf_len = sprintf(result + copied, "}\n");
    copied += buf_len;

    ZITI_LOG(TRACE, "Executing ADD NRPT script containing %d domains. total script size: %d", domains_size, copied);

    char cmd[MAX_POWERSHELL_SCRIPT_LEN];
    snprintf(cmd, sizeof(cmd),"powershell -Command \"%s\"", result);

    ZITI_LOG(TRACE, "executing '%s'", cmd);
    int rc = system(cmd);
    if (rc != 0) {
        ZITI_LOG(WARN, "ADD NRPT script: %d(err=%d)", rc, GetLastError());
    }
}

void add_nrpt_rules(model_map *hostnames, char* tun_ip) {

    if (model_map_size(hostnames) == 0) {
        ZITI_LOG(DEBUG, "No domains specified to add_nrpt_rules, exiting early");
        return;
    }
    int namespace_template_padding = strlen(namespace_template);
    LIST_HEAD(hostnames_list, hostname_s) host_names_list = LIST_HEAD_INITIALIZER(host_names_list);
    int current_size = 0;
    int rule_size = 0;
    model_map_iter it = model_map_iterator(hostnames);
    while(it != NULL) {
        char* hostname = model_map_it_key(it);
        if (current_size > MAX_BUCKET_SIZE || rule_size > MAX_POWERSHELL_SCRIPT_LEN) {
            chunked_add_nrpt_rules(&host_names_list, tun_ip);
            rule_size = strlen(hostname) + namespace_template_padding;
            current_size = 0;
        }

        struct hostname_s *hostname_data = calloc(1, sizeof (struct hostname_s));
        hostname_data->hostname = strdup(hostname);
        LIST_INSERT_HEAD(&host_names_list, hostname_data, _next);
        current_size++;
        rule_size += strlen(hostname) + namespace_template_padding;
        it = model_map_it_remove(it);
    }
    if (current_size > 0) {
        chunked_add_nrpt_rules(&host_names_list, tun_ip);
    }

}

void chunked_remove_nrpt_rules(LIST_HEAD(hostnames_list, hostname_s) *hostnames) {
    char* result = calloc(MAX_POWERSHELL_SCRIPT_LEN, sizeof(char));
    size_t buf_len = sprintf(result, "$toRemove = @(\n");
    size_t copied = buf_len;
    int domains_size = 0;

    while(!LIST_EMPTY(hostnames)) {
        struct hostname_s *hostname = LIST_FIRST(hostnames);
        buf_len = sprintf(result + copied, namespace_template, "\n", hostname);
        copied += buf_len;
        domains_size++;
        LIST_REMOVE(hostname, _next);
    }
    buf_len = sprintf(result + copied, "%s\n\n", ")");
    copied += buf_len;

    buf_len = sprintf(result + copied, "ForEach ($ns in $toRemove){\n");
    copied += buf_len;
    buf_len = sprintf(result + copied, "Get-DnsClientNrptRule | where Namespace -eq $ns['n'] | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue\n");
    copied += buf_len;
    buf_len = sprintf(result + copied, "}\n");
    copied += buf_len;

    ZITI_LOG(TRACE, "Executing Remove NRPT script containing %d domains. total script size: %d", domains_size, copied);

    char cmd[MAX_POWERSHELL_SCRIPT_LEN];
    snprintf(cmd, sizeof(cmd),"powershell -Command \"%s\"", result);

    ZITI_LOG(TRACE, "executing '%s'", cmd);
    int rc = system(cmd);
    if (rc != 0) {
        ZITI_LOG(WARN, "Remove NRPT script: %d(err=%d)", rc, GetLastError());
    }
}

void remove_nrpt_rules(model_map *hostnames) {

    if (model_map_size(hostnames) == 0) {
        ZITI_LOG(DEBUG, "No domains specified to remove_nrpt_rules, exiting early");
        return;
    }
    int namespace_template_padding = strlen(namespace_template);
    LIST_HEAD(hostnames_list, hostname_s) host_names_list = LIST_HEAD_INITIALIZER(host_names_list);
    int current_size = 0;
    int rule_size = 0;
    model_map_iter it = model_map_iterator(hostnames);
    while(it != NULL) {
        char* hostname = model_map_it_key(it);
        if (current_size > MAX_BUCKET_SIZE || rule_size > MAX_POWERSHELL_SCRIPT_LEN) {
            chunked_remove_nrpt_rules(&host_names_list);
            rule_size = strlen(hostname) + namespace_template_padding;
            current_size = 0;
        }

        struct hostname_s *hostname_data = calloc(1, sizeof (struct hostname_s));
        hostname_data->hostname = hostname;
        LIST_INSERT_HEAD(&host_names_list, hostname_data, _next);
        current_size++;
        rule_size += strlen(hostname) + namespace_template_padding;
        it = model_map_it_remove(it);
    }
    if (current_size > 0) {
        chunked_remove_nrpt_rules(&host_names_list);
    }
}

void remove_all_nrpt_rules() {
    char* result = calloc(MAX_POWERSHELL_SCRIPT_LEN, sizeof(char));
    size_t buf_len = sprintf(result, "Get-DnsClientNrptRule | Where { $_.Comment.StartsWith('Added by %s') } | Remove-DnsClientNrptRule -ErrorAction SilentlyContinue -Force", exe_name);
    ZITI_LOG(TRACE, "Removing all nrpt rules. total script size: %d", buf_len);

    char cmd[MAX_POWERSHELL_SCRIPT_LEN];
    snprintf(cmd, sizeof(cmd),"powershell -Command \"%s\"", result);

    ZITI_LOG(TRACE, "executing '%s'", cmd);
    int rc = system(cmd);
    if (rc != 0) {
        ZITI_LOG(WARN, "Remove all NRPT script: %d(err=%d)", rc, GetLastError());
    }
}

void remove_single_nrpt_rule(char* nrpt_rule) {
    char* result = calloc(MAX_POWERSHELL_SCRIPT_LEN, sizeof(char));
    size_t buf_len = sprintf(result, "Get-DnsClientNrptRule | where Namespace -eq '%s' | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue", nrpt_rule);
    ZITI_LOG(TRACE, "Removing nrpt rule. total script size: %d", buf_len);

    char cmd[MAX_POWERSHELL_SCRIPT_LEN];
    snprintf(cmd, sizeof(cmd),"powershell -Command \"%s\"", result);

    ZITI_LOG(TRACE, "executing '%s'", cmd);
    int rc = system(cmd);
    if (rc != 0) {
        ZITI_LOG(WARN, "Delete single NRPT rule: %d(err=%d)", rc, GetLastError());
    }
}

bool is_nrpt_policies_effective(char* tns_ip) {
    char* result = calloc(MAX_POWERSHELL_SCRIPT_LEN, sizeof(char));
    size_t buf_len = sprintf(result, "Add-DnsClientNrptRule -Namespace '.ziti.test' -NameServers '%s' -Comment 'Added by ziti-tunnel' -DisplayName 'ziti-tunnel:.ziti.test'\n"
                                     "Get-DnsClientNrptPolicy -Effective | Select-Object Namespace -Unique | Where-Object Namespace -Eq '.ziti.test'",tns_ip);
    ZITI_LOG(TRACE, "Removing all nrpt rules. total script size: %d", buf_len);

    char cmd[MAX_POWERSHELL_SCRIPT_LEN];
    snprintf(cmd, sizeof(cmd),"powershell -Command \"%s\"", result);

    ZITI_LOG(TRACE, "executing '%s'", cmd);
    int rc = system(cmd);
    if (rc != 0) {
        ZITI_LOG(WARN, "Remove all NRPT script: %d(err=%d)", rc, GetLastError());
        return false;
    } else {
        ZITI_LOG(INFO, "NRPT policies are effective in this system");
        remove_single_nrpt_rule(".ziti.test");
        return true;
    }
}

#endif
