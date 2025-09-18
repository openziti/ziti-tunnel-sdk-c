/*
 Copyright NetFoundry Inc.

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
#define MIN_BUFFER_LEN 512

static char* const namespace_template = "%s@{n='%s';}";

struct hostname_s {
    char *hostname;
    LIST_ENTRY(hostname_s) _next;
};
typedef LIST_HEAD(hostname_list_s, hostname_s) hostname_list_t;

static void exit_cb(uv_process_t* process,
                    int64_t exit_status,
                    int term_signal) {
    ZITI_LOG(TRACE, "Process exited with status %lld, signal %d", exit_status, term_signal);
    uv_close((uv_handle_t*)process, (uv_close_cb) free);
}

static bool is_buffer_available(size_t buf_len, size_t max_size, char* script) {
    if (buf_len < 0 || buf_len >= max_size) {
        ZITI_LOG(ERROR,"Not enough buffer space to hold the data. Partial data fetched : %s", script);
        return false;
    }
    return true;
}

static bool exec_process(uv_loop_t *ziti_loop, const char* program, char* args[]) {
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

static char* exec_process_fetch_result(const char* program) {
    FILE *fp;
    char path[BUFFER_SIZE];

    fp = _popen(program, "r");
    if (fp == NULL) {
        ZITI_LOG(ERROR,"Failed to run command %s", strerror(errno));
        return NULL;
    }
    char* result = calloc(MAXBUFFERLEN, sizeof(char));

    while (fgets(path, sizeof(path), fp) != NULL) {
        if (is_buffer_available(strlen(result) + strlen(path), MAXBUFFERLEN, result)) {
            strcat(result, path);
        } else {
            free(result);
            result = NULL;
            break;
        }
    }

    _pclose(fp);

    return result;
}

// a function to remove the leading star from a "hostname" when specified from as an intercept
const char *normalize_hostname(char *hostname) {
    if(hostname) {
        if (hostname[0] == '*') {
            return &hostname[1];
        }
    }
    return hostname;
}

void chunked_add_nrpt_rules(uv_loop_t *ziti_loop, hostname_list_t *hostnames, const char* tun_ip) {
    char script[MAX_POWERSHELL_SCRIPT_LEN] = { 0 };
    size_t buf_len = snprintf(script, MAX_POWERSHELL_SCRIPT_LEN, "$Namespaces = @(");
    if (!is_buffer_available(buf_len, MAX_POWERSHELL_SCRIPT_LEN, script)) {
        return;
    }
    size_t copied = buf_len;
    int domains_size = 0;

    while(!LIST_EMPTY(hostnames)) {
        struct hostname_s *hostname = LIST_FIRST(hostnames);
        buf_len = snprintf(script + copied, (MAX_POWERSHELL_SCRIPT_LEN - copied), namespace_template, "\n", normalize_hostname(hostname->hostname));
        if (!is_buffer_available(buf_len, (MAX_POWERSHELL_SCRIPT_LEN - copied), script)) {
            return;
        }
        copied += buf_len;
        domains_size++;
        LIST_REMOVE(hostname, _next);
        free(hostname->hostname);
        free(hostname);
    }
    buf_len = snprintf(script + copied, (MAX_POWERSHELL_SCRIPT_LEN - copied), ")\n\n");
    if (!is_buffer_available(buf_len, (MAX_POWERSHELL_SCRIPT_LEN - copied), script)) {
        return;
    }
    copied += buf_len;

    buf_len = snprintf(script + copied, (MAX_POWERSHELL_SCRIPT_LEN - copied), "ForEach ($Namespace in $Namespaces) {\n");
    if (!is_buffer_available(buf_len, (MAX_POWERSHELL_SCRIPT_LEN - copied), script)) {
        return;
    }
    copied += buf_len;
    buf_len = snprintf(script + copied, (MAX_POWERSHELL_SCRIPT_LEN - copied), "$ns=$Namespace['n']\n");
    if (!is_buffer_available(buf_len, (MAX_POWERSHELL_SCRIPT_LEN - copied), script)) {
        return;
    }
    copied += buf_len;
    buf_len = snprintf(script + copied, (MAX_POWERSHELL_SCRIPT_LEN - copied), "$Rule = @{Namespace=${ns}; NameServers=@('%s'); Comment='Added by %s'; DisplayName='%s:'+${ns}; }\n", tun_ip, DEFAULT_EXECUTABLE_NAME, DEFAULT_EXECUTABLE_NAME);
    if (!is_buffer_available(buf_len, (MAX_POWERSHELL_SCRIPT_LEN - copied), script)) {
        return;
    }
    copied += buf_len;
    buf_len = snprintf(script + copied, (MAX_POWERSHELL_SCRIPT_LEN - copied), "Add-DnsClientNrptRule @Rule\n");
    if (!is_buffer_available(buf_len, (MAX_POWERSHELL_SCRIPT_LEN - copied), script)) {
        return;
    }
    copied += buf_len;
    buf_len = snprintf(script + copied, (MAX_POWERSHELL_SCRIPT_LEN - copied), "}\n");
    if (!is_buffer_available(buf_len, (MAX_POWERSHELL_SCRIPT_LEN - copied), script)) {
        return;
    }
    copied += buf_len;

    ZITI_LOG(TRACE, "Adding %d domains using NRPT script. Total script size: %zd", domains_size, copied);

    char cmd[MAX_POWERSHELL_COMMAND_LEN];
    buf_len = snprintf(cmd, sizeof(cmd),"powershell -Command \"%s\"", script);
    if (!is_buffer_available(buf_len, MAX_POWERSHELL_COMMAND_LEN, cmd)) {
        return;
    }

    ZITI_LOG(DEBUG, "Executing Add domains NRPT script :");
    ZITI_LOG(DEBUG, "%s", cmd);
    char* args[] = {"powershell", "-Command", script, NULL};
    bool result = exec_process(ziti_loop, args[0], args);
    if (!result) {
        ZITI_LOG(WARN, "Add domains NRPT script: %d(err=%lu)", result, GetLastError());
    } else {
        ZITI_LOG(DEBUG, "Added domains using NRPT script");
    }
}

void add_nrpt_rules(uv_loop_t *nrpt_loop, model_map *hostnames, const char* dns_ip) {
    ZITI_LOG(VERBOSE, "Add nrpt rules");

    if (hostnames == NULL || model_map_size(hostnames) == 0) {
        ZITI_LOG(DEBUG, "No domains specified to add_nrpt_rules, exiting early");
        return;
    }
    size_t namespace_template_padding = strlen(namespace_template);
    hostname_list_t host_names_list = LIST_HEAD_INITIALIZER(host_names_list);
    int current_size = 0;
    size_t rule_size = MIN_BUFFER_LEN;
    model_map_iter it = model_map_iterator(hostnames);
    while(it != NULL) {
        const char* hostname = model_map_it_key(it);
        if (current_size > MAX_BUCKET_SIZE || rule_size > MAX_POWERSHELL_SCRIPT_LEN) {
            chunked_add_nrpt_rules(nrpt_loop, &host_names_list, dns_ip);
            rule_size = MIN_BUFFER_LEN;
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
}

void chunked_remove_nrpt_rules(uv_loop_t *ziti_loop, hostname_list_t *hostnames) {
    char script[MAX_POWERSHELL_SCRIPT_LEN] = { 0 };
    size_t buf_len = snprintf(script, MAX_POWERSHELL_SCRIPT_LEN, "$toRemove = @(\n");
    if (!is_buffer_available(buf_len, MAX_POWERSHELL_SCRIPT_LEN, script)) {
        return;
    }
    size_t copied = buf_len;
    int domains_size = 0;

    while(!LIST_EMPTY(hostnames)) {
        struct hostname_s *hostname = LIST_FIRST(hostnames);
        buf_len = snprintf(script + copied, (MAX_POWERSHELL_SCRIPT_LEN - copied), namespace_template, "\n", normalize_hostname(hostname->hostname));
        copied += buf_len;
        domains_size++;
        LIST_REMOVE(hostname, _next);
        free(hostname->hostname);
        free(hostname);
    }
    buf_len = snprintf(script + copied, (MAX_POWERSHELL_SCRIPT_LEN - copied), "%s\n\n", ")");
    if (!is_buffer_available(buf_len, (MAX_POWERSHELL_SCRIPT_LEN - copied), script)) {
        return;
    }
    copied += buf_len;

    buf_len = snprintf(script + copied, (MAX_POWERSHELL_SCRIPT_LEN - copied), "ForEach ($ns in $toRemove){\n");
    if (!is_buffer_available(buf_len, (MAX_POWERSHELL_SCRIPT_LEN - copied), script)) {
        return;
    }
    copied += buf_len;
    buf_len = snprintf(script + copied, (MAX_POWERSHELL_SCRIPT_LEN - copied), "Get-DnsClientNrptRule | where Namespace -eq $ns['n'] | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue\n");
    if (!is_buffer_available(buf_len, (MAX_POWERSHELL_SCRIPT_LEN - copied), script)) {
        return;
    }
    copied += buf_len;
    buf_len = snprintf(script + copied, (MAX_POWERSHELL_SCRIPT_LEN - copied), "}\n");
    if (!is_buffer_available(buf_len, (MAX_POWERSHELL_SCRIPT_LEN - copied), script)) {
        return;
    }
    copied += buf_len;

    ZITI_LOG(TRACE, "Removing %d domains using NRPT script. total script size: %zd", domains_size, copied);

    char cmd[MAX_POWERSHELL_COMMAND_LEN];
    buf_len = snprintf(cmd, sizeof(cmd),"powershell -Command \"%s\"", script);
    if (!is_buffer_available(buf_len, MAX_POWERSHELL_COMMAND_LEN, script)) {
        return;
    }

    ZITI_LOG(DEBUG, "Executing Remove domains NRPT script: ");
    ZITI_LOG(DEBUG, "%s", cmd);
    char* args[] = {"powershell", "-Command", script, NULL};
    bool result = exec_process(ziti_loop, args[0], args);
    if (!result) {
        ZITI_LOG(WARN, "Remove domains NRPT script: %d(err=%lu)", result, GetLastError());
    } else {
        ZITI_LOG(DEBUG, "Removed domains using NRPT script");
    }
}

void remove_nrpt_rules(uv_loop_t *nrpt_loop, model_map *hostnames) {
    ZITI_LOG(VERBOSE, "Remove nrpt rules");

    if (hostnames == NULL || model_map_size(hostnames) == 0) {
        ZITI_LOG(DEBUG, "No domains specified to remove_nrpt_rules, exiting early");
        return;
    }
    size_t namespace_template_padding = strlen(namespace_template);
    hostname_list_t host_names_list = LIST_HEAD_INITIALIZER(host_names_list);
    int current_size = 0;
    size_t rule_size = MIN_BUFFER_LEN;
    model_map_iter it = model_map_iterator(hostnames);
    while(it != NULL) {
        const char* hostname = model_map_it_key(it);
        if (current_size > MAX_BUCKET_SIZE || rule_size > MAX_POWERSHELL_SCRIPT_LEN) {
            chunked_remove_nrpt_rules(nrpt_loop, &host_names_list);
            rule_size = MIN_BUFFER_LEN;
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
        chunked_remove_nrpt_rules(nrpt_loop, &host_names_list);
    }
}

char* get_nrpt_comment(const char* zet_id, bool exact) {
    char *nrpt_filter;
    const char *name;
    char *format;
    if (exact) {
        name = zet_id;
        format = "$_.Comment -eq 'Added by %s'";
    } else {
        // remove any rules starting with the common prefix
        name = DEFAULT_EXECUTABLE_NAME;
        format = "$_.Comment.StartsWith('Added by %s')";
    }
    size_t tot_chars = strlen(format) + strlen(name);
    nrpt_filter = calloc(tot_chars + 1, sizeof(char));
    snprintf(nrpt_filter, tot_chars, format, name);
    return nrpt_filter;
}

void remove_all_nrpt_rules(const char* zet_id, bool exact) {
    char remove_cmd[MAX_POWERSHELL_COMMAND_LEN];

    char* nrpt_filter = get_nrpt_comment(zet_id, exact);
    ZITI_LOG(INFO, "removing NRPT rules matching filter: %s", nrpt_filter);
    size_t buf_len = snprintf(remove_cmd, MAX_POWERSHELL_COMMAND_LEN, "powershell -Command \"Get-DnsClientNrptRule | Where { %s } | Remove-DnsClientNrptRule -ErrorAction SilentlyContinue -Force\"", nrpt_filter);
    free(nrpt_filter);

    ZITI_LOG(TRACE, "Removing all nrpt rules. total script size: %zd", buf_len);

    ZITI_LOG(DEBUG, "Executing Remove all nrpt rules: '%s'", remove_cmd);
    int rc = system(remove_cmd);
    if (rc != 0) {
        ZITI_LOG(WARN, "Remove all NRPT script: %d(err=%lu)", rc, GetLastError());
    } else {
        ZITI_LOG(DEBUG, "Removed all nrpt rules");
    }
}

void chunked_remove_and_add_nrpt_rules(uv_loop_t *ziti_loop, hostname_list_t *hostnames, const char* dns_ip) {
    char script[MAX_POWERSHELL_SCRIPT_LEN] = { 0 };
    size_t buf_len = snprintf(script, MAX_POWERSHELL_SCRIPT_LEN, "$toRemoveAndAdd = @(\n");
    if (!is_buffer_available(buf_len, MAX_POWERSHELL_SCRIPT_LEN, script)) {
        return;
    }
    size_t copied = buf_len;
    int domains_size = 0;

    while(!LIST_EMPTY(hostnames)) {
        struct hostname_s *hostname = LIST_FIRST(hostnames);
        buf_len = snprintf(script + copied, (MAX_POWERSHELL_SCRIPT_LEN - copied), namespace_template, "\n", normalize_hostname(hostname->hostname));
        copied += buf_len;
        domains_size++;
        LIST_REMOVE(hostname, _next);
        free(hostname->hostname);
        free(hostname);
    }
    buf_len = snprintf(script + copied, (MAX_POWERSHELL_SCRIPT_LEN - copied), "%s\n\n", ")");
    if (!is_buffer_available(buf_len, (MAX_POWERSHELL_SCRIPT_LEN - copied), script)) {
        return;
    }
    copied += buf_len;

    buf_len = snprintf(script + copied, (MAX_POWERSHELL_SCRIPT_LEN - copied), "ForEach ($ns in $toRemoveAndAdd){\n");
    if (!is_buffer_available(buf_len, (MAX_POWERSHELL_SCRIPT_LEN - copied), script)) {
        return;
    }
    copied += buf_len;
    buf_len = snprintf(script + copied, (MAX_POWERSHELL_SCRIPT_LEN - copied), "Get-DnsClientNrptRule | where Namespace -eq $ns['n'] | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue\n");
    if (!is_buffer_available(buf_len, (MAX_POWERSHELL_SCRIPT_LEN - copied), script)) {
        return;
    }
    copied += buf_len;
    buf_len = snprintf(script + copied, (MAX_POWERSHELL_SCRIPT_LEN - copied), "$nsToAdd=$ns['n']\n");
    if (!is_buffer_available(buf_len, (MAX_POWERSHELL_SCRIPT_LEN - copied), script)) {
        return;
    }
    copied += buf_len;
    buf_len = snprintf(script + copied, (MAX_POWERSHELL_SCRIPT_LEN - copied), "$Rule = @{Namespace=${nsToAdd}; NameServers=@('%s'); Comment='Added by %s'; DisplayName='%s:'+${ns}; }\n", dns_ip, DEFAULT_EXECUTABLE_NAME, DEFAULT_EXECUTABLE_NAME);
    if (!is_buffer_available(buf_len, (MAX_POWERSHELL_SCRIPT_LEN - copied), script)) {
        return;
    }
    copied += buf_len;
    buf_len = snprintf(script + copied, (MAX_POWERSHELL_SCRIPT_LEN - copied), "Add-DnsClientNrptRule @Rule\n");
    if (!is_buffer_available(buf_len, (MAX_POWERSHELL_SCRIPT_LEN - copied), script)) {
        return;
    }
    copied += buf_len;
    buf_len = snprintf(script + copied, (MAX_POWERSHELL_SCRIPT_LEN - copied), "}\n");
    if (!is_buffer_available(buf_len, (MAX_POWERSHELL_SCRIPT_LEN - copied), script)) {
        return;
    }
    copied += buf_len;

    ZITI_LOG(TRACE, "Removing and adding %d domains using NRPT script. total script size: %zd", domains_size, copied);

    char cmd[MAX_POWERSHELL_COMMAND_LEN];
    buf_len = snprintf(cmd, sizeof(cmd),"powershell -Command \"%s\"", script);
    if (!is_buffer_available(buf_len, MAX_POWERSHELL_COMMAND_LEN, script)) {
        return;
    }

    ZITI_LOG(DEBUG, "Executing Remove and add domains NRPT script: ");
    ZITI_LOG(DEBUG, "%s", cmd);
    char* args[] = {"powershell", "-Command", script, NULL};
    bool result = exec_process(ziti_loop, args[0], args);
    if (!result) {
        ZITI_LOG(WARN, "Remove and add domains NRPT script: %d(err=%lu)", result, GetLastError());
    } else {
        ZITI_LOG(DEBUG, "Removed and added domains using NRPT script");
    }
}

void remove_and_add_nrpt_rules(uv_loop_t *nrpt_loop, model_map *hostnames, const char* dns_ip) {
    ZITI_LOG(VERBOSE, "Remove and add nrpt rules");

    if (hostnames == NULL || model_map_size(hostnames) == 0) {
        ZITI_LOG(DEBUG, "No domains specified to remove_and_add_nrpt_rules, exiting early");
        return;
    }
    size_t namespace_template_padding = strlen(namespace_template);
    hostname_list_t host_names_list = LIST_HEAD_INITIALIZER(host_names_list);
    int current_size = 0;
    size_t rule_size = MIN_BUFFER_LEN;
    model_map_iter it = model_map_iterator(hostnames);
    while(it != NULL) {
        const char* hostname = model_map_it_key(it);
        if (current_size > MAX_BUCKET_SIZE || rule_size > MAX_POWERSHELL_SCRIPT_LEN) {
            chunked_remove_and_add_nrpt_rules(nrpt_loop, &host_names_list, dns_ip);
            rule_size = MIN_BUFFER_LEN;
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
        chunked_remove_and_add_nrpt_rules(nrpt_loop, &host_names_list, dns_ip);
    }
}

void remove_single_nrpt_rule(char* nrpt_rule) {
    char remove_cmd[MAX_POWERSHELL_COMMAND_LEN];
    size_t buf_len = sprintf(remove_cmd, "powershell -Command \"Get-DnsClientNrptRule | where Namespace -eq '%s' | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue\"", nrpt_rule);
    ZITI_LOG(TRACE, "Removing nrpt rule. total script size: %zd", buf_len);

    ZITI_LOG(DEBUG, "Executing Remove nrpt rule: %s", remove_cmd);
    int rc = system(remove_cmd);
    if (rc != 0) {
        ZITI_LOG(WARN, "Delete single NRPT rule: %d(err=%lu)", rc, GetLastError());
    } else {
        ZITI_LOG(DEBUG, "Removed nrpt rules");
    }
}

bool is_nrpt_policies_effective(const char* tns_ip, char* zet_id) {
    char add_cmd[MAX_POWERSHELL_COMMAND_LEN];
    size_t buf_len = sprintf(add_cmd, "powershell -Command \"Add-DnsClientNrptRule -Namespace '.ziti.test' -NameServers '%s' -Comment 'Added by %s' -DisplayName '%s:.ziti.test'\"",tns_ip, zet_id, zet_id);
    ZITI_LOG(TRACE, "add test nrpt rule. total script size: %zd", buf_len);

    ZITI_LOG(DEBUG, "Executing add test nrpt rule. %s", add_cmd);
    int rc = system(add_cmd);
    if (rc != 0) {
        ZITI_LOG(WARN, "Add test NRPT rule: %d(err=%lu)", rc, GetLastError());
        return false;
    }

    const char* get_cmd = "powershell -Command \"(Get-DnsClientNrptPolicy -Effective | Select-Object Namespace -Unique | Where-Object Namespace -Eq '.ziti.test' | Measure-Object).Count\"";
    char* result = exec_process_fetch_result(get_cmd);
    if (result == NULL) {
        ZITI_LOG(WARN, "get test nrpt rule script failed");
        return false;
    } else {
        boolean policy_found = false;
        errno = 0;
        long n = strtol(result, NULL, 10);
        if (errno == 0) {
            ZITI_LOG(DEBUG, "test nrpt rule query returned %ld items", n);
            policy_found = (n > 0);
        } else {
            ZITI_LOG(ERROR, "strtol(%s) failed: e=%d", result, errno);
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

void update_interface_metric(uv_loop_t *ziti_loop, const char *tun_name, int metric) {
    char script[MAX_POWERSHELL_SCRIPT_LEN] = { 0 };
    size_t buf_len = sprintf(script, "$i=Get-NetIPInterface | Where -FilterScript {$_.InterfaceAlias -Eq \"%s\"}; ", tun_name);
    size_t copied = buf_len;
    buf_len = sprintf(script + copied, "Set-NetIPInterface -InterfaceIndex $i.ifIndex -InterfaceMetric %d", metric);
    copied += buf_len;

    ZITI_LOG(TRACE, "Updating Interface metric using script. total script size: %zd", copied);

    char cmd[MAX_POWERSHELL_COMMAND_LEN];
    snprintf(cmd, sizeof(cmd),"powershell -Command \"%s\"", script);

    ZITI_LOG(DEBUG, "Executing Update Interface metric script :");
    ZITI_LOG(DEBUG, "%s", cmd);
    char* args[] = {"powershell", "-Command", script, NULL};
    bool result = exec_process(ziti_loop, args[0], args);
    if (!result) {
        ZITI_LOG(WARN, "Update Interface metric script: %d(err=%lu)", result, GetLastError());
    } else {
        ZITI_LOG(DEBUG, "Updated Interface metric");
    }
}

void update_symlink(uv_loop_t *symlink_loop, char* symlink, char* filename) {
    char script[MAX_POWERSHELL_SCRIPT_LEN] = { 0 };
    size_t buf_len = sprintf(script, "Get-Item -Path \"%s\" | Remove-Item;", symlink);
    size_t copied = buf_len;
    buf_len = sprintf(script + copied, "New-Item -Itemtype SymbolicLink -Path \"%s\" -Target \"%s\" | Out-Null", symlink, filename);
    copied += buf_len;

    ZITI_LOG(TRACE, "Updating symlink using script. total script size: %zd", copied);

    char cmd[MAX_POWERSHELL_COMMAND_LEN];
    snprintf(cmd, sizeof(cmd),"powershell -Command \"%s\"", script);

    ZITI_LOG(DEBUG, "Executing update symlink script :");
    ZITI_LOG(DEBUG, "%s", cmd);
    char* args[] = {"powershell", "-Command", script, NULL};
    bool result = exec_process(symlink_loop, args[0], args);
    if (!result) {
        ZITI_LOG(WARN, "Update symlink script: %d(err=%lu)", result, GetLastError());
    } else {
        ZITI_LOG(DEBUG, "Updated symlink script");
    }
}