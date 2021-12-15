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

#include <ziti/ziti_log.h>
#include <model/dtos.h>
#include "ziti/ziti_tunnel.h"
#include "windows/windows-scripts.h"

#define MAX_BUCKET_SIZE 512

static char* const namespace_template = "%s@{n='%s';}";
static char* const exe_name = "ziti-tunnel";

struct hostname_s {
    char *hostname;
    LIST_ENTRY(hostname_s) _next;
};

static void exit_cb(uv_process_t* process,
                    int64_t exit_status,
                    int term_signal) {
    ZITI_LOG(TRACE, "Process exited with status %d, signal %d", exit_status, term_signal);
    uv_close((uv_handle_t*)process, (uv_close_cb) free);
}

static bool exec_process(uv_loop_t *ziti_loop, char* program, char* args[]) {
    uv_process_t* process = calloc(1, sizeof(uv_process_t));
    uv_process_options_t options = {0};
    uv_stdio_container_t stdio[3];
    options.file = program;
    options.args = args;
    options.exit_cb = exit_cb;

    options.stdio = stdio;
    options.stdio_count = 3;
    options.stdio[0].flags = UV_IGNORE;
    options.stdio[1].flags = UV_INHERIT_FD;
    options.stdio[1].data.fd = 1;
    options.stdio[2].flags = UV_INHERIT_FD;
    options.stdio[2].data.fd = 2;

    int r = uv_spawn(ziti_loop, process, &options);
    if (r != 0) {
        ZITI_LOG(ERROR, "Could not execute the command due to %s", uv_err_name(r));
        return false;
    }
    uv_unref((uv_handle_t*) process);
    return true;
}

static char* exec_process_fetch_result(char* program) {
    FILE *fp;
    char path[BUFFER_SIZE];

    fp = popen(program, "r");
    if (fp == NULL) {
        ZITI_LOG(ERROR,"Failed to run command %s", strerror(errno));
        return NULL;
    }
    char* result = calloc(MAXBUFFERLEN, sizeof(char));

    while (fgets(path, sizeof(path), fp) != NULL) {
        strcat(result, path);
    }

    pclose(fp);

    return result;
}

void chunked_add_nrpt_rules(uv_loop_t *ziti_loop, LIST_HEAD(hostnames_list, hostname_s) *hostnames, char* tun_ip) {
    char* script = calloc(MAX_POWERSHELL_SCRIPT_LEN, sizeof(char));
    size_t buf_len = sprintf(script, "$Namespaces = @(");
    size_t copied = buf_len;
    int domains_size = 0;

    while(!LIST_EMPTY(hostnames)) {
        struct hostname_s *hostname = LIST_FIRST(hostnames);
        buf_len = sprintf(script + copied, namespace_template, "\n", hostname->hostname);
        copied += buf_len;
        domains_size++;
        LIST_REMOVE(hostname, _next);
        free(hostname->hostname);
        free(hostname);
    }
    buf_len = sprintf(script + copied, "%s\n\n", ")");
    copied += buf_len;

    buf_len = sprintf(script + copied, "ForEach ($Namespace in $Namespaces) {\n");
    copied += buf_len;
    buf_len = sprintf(script + copied, "$ns=$Namespace['n']\n");
    copied += buf_len;
    buf_len = sprintf(script + copied, "$Rule = @{Namespace=${ns}; NameServers=@('%s'); Comment='Added by %s'; DisplayName='%s:'+${ns}; }\n", tun_ip, exe_name, exe_name);
    copied += buf_len;
    buf_len = sprintf(script + copied, "Add-DnsClientNrptRule @Rule\n");
    copied += buf_len;
    buf_len = sprintf(script + copied, "}\n");
    copied += buf_len;

    ZITI_LOG(TRACE, "Adding NRPT script containing %d domains. total script size: %d", domains_size, copied);

    char cmd[MAX_POWERSHELL_COMMAND_LEN];
    snprintf(cmd, sizeof(cmd),"powershell -Command \"%s\"", script);

    ZITI_LOG(INFO, "Executing ADD NRPT script :");
    ZITI_LOG(INFO, "%s", cmd);
    char* args[] = {"powershell", "-Command", script, NULL};
    bool result = exec_process(ziti_loop, args[0], args);
    if (!result) {
        ZITI_LOG(WARN, "ADD NRPT script: %d(err=%d)", result, GetLastError());
    }
    free(script);
}

void add_nrpt_rules_script(uv_loop_t *nrpt_loop, struct add_service_nrpt_req *add_svc_req_data) {
    model_map *hostnames = add_svc_req_data->hostnames;
    char* dns_ip = add_svc_req_data->dns_ip;
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
            chunked_add_nrpt_rules(nrpt_loop, &host_names_list, dns_ip);
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
        chunked_add_nrpt_rules(nrpt_loop, &host_names_list, dns_ip);
    }
    add_svc_req_data->dns_ip = NULL;
    free(hostnames);
    free(add_svc_req_data);
}

void add_nrpt_rules(uv_async_t *ar) {
    ZITI_LOG(VERBOSE, "Add nrpt rules");

    struct add_service_nrpt_req *add_svc_req_data = ar->data;
    uv_loop_t *nrpt_loop = ar->loop;

    uv_close((uv_handle_t *) ar, (uv_close_cb) free);

    add_nrpt_rules_script(nrpt_loop, add_svc_req_data);
}

void chunked_remove_nrpt_rules(uv_loop_t *ziti_loop, LIST_HEAD(hostnames_list, hostname_s) *hostnames) {
    char* script = calloc(MAX_POWERSHELL_SCRIPT_LEN, sizeof(char));
    size_t buf_len = sprintf(script, "$toRemove = @(\n");
    size_t copied = buf_len;
    int domains_size = 0;

    while(!LIST_EMPTY(hostnames)) {
        struct hostname_s *hostname = LIST_FIRST(hostnames);
        buf_len = sprintf(script + copied, namespace_template, "\n", hostname);
        copied += buf_len;
        domains_size++;
        LIST_REMOVE(hostname, _next);
    }
    buf_len = sprintf(script + copied, "%s\n\n", ")");
    copied += buf_len;

    buf_len = sprintf(script + copied, "ForEach ($ns in $toRemove){\n");
    copied += buf_len;
    buf_len = sprintf(script + copied, "Get-DnsClientNrptRule | where Namespace -eq $ns['n'] | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue\n");
    copied += buf_len;
    buf_len = sprintf(script + copied, "}\n");
    copied += buf_len;

    ZITI_LOG(TRACE, "Removing NRPT script containing %d domains. total script size: %d", domains_size, copied);

    char cmd[MAX_POWERSHELL_COMMAND_LEN];
    snprintf(cmd, sizeof(cmd),"powershell -Command \"%s\"", script);

    ZITI_LOG(INFO, "Executing Remove NRPT script: ");
    ZITI_LOG(INFO, "%s", cmd);
    char* args[] = {"powershell", "-Command", script, NULL};
    bool result = exec_process(ziti_loop, args[0], args);
    if (!result) {
        ZITI_LOG(WARN, "Remove NRPT script: %s(err=%d)", result, GetLastError());
    }
    free(script);
}

void remove_nrpt_rules_script(uv_loop_t *nrpt_loop, model_map *hostnames) {
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
        if (current_size > MAX_BUCKET_SIZE || rule_size > MAX_POWERSHELL_COMMAND_LEN) {
            chunked_remove_nrpt_rules(nrpt_loop, &host_names_list);
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
        chunked_remove_nrpt_rules(nrpt_loop, &host_names_list);
    }
    free(hostnames);
}

void remove_nrpt_rules(uv_async_t *ar) {
    ZITI_LOG(VERBOSE, "Remove nrpt rules");
    model_map *hostnames = ar->data;
    uv_loop_t *nrpt_loop = ar->loop;

    uv_close((uv_handle_t *) ar, (uv_close_cb) free);

    remove_nrpt_rules_script(nrpt_loop, hostnames);
}

void remove_all_nrpt_rules() {
    char remove_cmd[MAX_POWERSHELL_COMMAND_LEN];
    size_t buf_len = sprintf(remove_cmd, "powershell -Command \"Get-DnsClientNrptRule | Where { $_.Comment.StartsWith('Added by %s') } | Remove-DnsClientNrptRule -ErrorAction SilentlyContinue -Force\"", exe_name);
    ZITI_LOG(TRACE, "Removing all nrpt rules. total script size: %d", buf_len);

    ZITI_LOG(INFO, "Executing Remove all nrpt rules: '%s'", remove_cmd);
    int rc = system(remove_cmd);
    if (rc != 0) {
        ZITI_LOG(WARN, "Remove all NRPT script: %d(err=%d)", rc, GetLastError());
    }
}

void remove_and_add_nrpt_rules(uv_async_t *ar) {
    ZITI_LOG(VERBOSE, "Remove and add nrpt rules");
    struct modify_service_nrpt_req *modify_svc_req_data = ar->data;
    uv_loop_t *nrpt_loop = ar->loop;

    struct add_service_nrpt_req *add_svc_req_data = calloc(1, sizeof(struct add_service_nrpt_req));

    uv_close((uv_handle_t *) ar, (uv_close_cb) free);

    remove_nrpt_rules_script(nrpt_loop, modify_svc_req_data->hostnamesToRemove);
    add_nrpt_rules_script(nrpt_loop, add_svc_req_data);

}

void remove_single_nrpt_rule(char* nrpt_rule) {
    char remove_cmd[MAX_POWERSHELL_COMMAND_LEN];
    size_t buf_len = sprintf(remove_cmd, "powershell -Command \"Get-DnsClientNrptRule | where Namespace -eq '%s' | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue\"", nrpt_rule);
    ZITI_LOG(TRACE, "Removing nrpt rule. total script size: %d", buf_len);

    ZITI_LOG(INFO, "Executing Remove nrpt rule: %s", remove_cmd);
    int rc = system(remove_cmd);
    if (rc != 0) {
        ZITI_LOG(WARN, "Delete single NRPT rule: %d(err=%d)", rc, GetLastError());
    }
}

bool is_nrpt_policies_effective(char* tns_ip) {
    char add_cmd[MAX_POWERSHELL_COMMAND_LEN];
    size_t buf_len = sprintf(add_cmd, "powershell -Command \"Add-DnsClientNrptRule -Namespace '.ziti.test' -NameServers '%s' -Comment 'Added by ziti-tunnel' -DisplayName 'ziti-tunnel:.ziti.test'\"",tns_ip);
    ZITI_LOG(TRACE, "add test nrpt rule. total script size: %d", buf_len);

    ZITI_LOG(INFO, "Executing add test nrpt rule. %s", add_cmd);
    int rc = system(add_cmd);
    if (rc != 0) {
        ZITI_LOG(WARN, "Add test NRPT rule: %d(err=%d)", rc, GetLastError());
        return false;
    }

    char get_cmd[MAX_POWERSHELL_COMMAND_LEN] = "powershell -Command \"Get-DnsClientNrptPolicy -Effective | Select-Object Namespace -Unique | Where-Object Namespace -Eq '.ziti.test'\"";
    char* result = exec_process_fetch_result(get_cmd);
    if (result == NULL) {
        ZITI_LOG(WARN, "get test nrpt rule script failed");
        return false;
    } else {
        char delim[] = "\r\n";
        char *token;
        boolean policy_found = false;

        token = strtok(result, delim);
        while( token != NULL ) {
            if (strcmp(token, ".ziti.test") == 0) {
                policy_found = true;
                break;
            }
            token = strtok(NULL, delim);
        }
        free(result);

        if (policy_found) {
            ZITI_LOG(INFO, "NRPT policies are effective in this system");
            remove_single_nrpt_rule(".ziti.test");
            return true;
        } else {
            ZITI_LOG(INFO, "NRPT policies are ineffective in this system");
            return false;
        }

    }
}

model_map *get_connection_specific_domains() {
    char get_cmd[MAX_POWERSHELL_COMMAND_LEN] = "powershell -Command \"Get-DnsClient | Select-Object ConnectionSpecificSuffix -Unique | ForEach-Object { $_.ConnectionSpecificSuffix }; (Get-DnsClientGlobalSetting).SuffixSearchList\"";
    ZITI_LOG(INFO, "Getting Connection specific Domains '%s'", get_cmd);

    char* result = exec_process_fetch_result(get_cmd);
    model_map *conn_sp_domains = calloc(1, sizeof(model_map));
    if (result == NULL) {
        ZITI_LOG(WARN, "get test nrpt rule script failed");
        return conn_sp_domains;
    } else {
        char delim[] = "\r\n";
        char *token = strtok(result, delim);
        while( token != NULL ) {
            model_map_set(conn_sp_domains, token, true);
            token = strtok(NULL, delim);
        }
        free(result);

        return conn_sp_domains;
    }
}