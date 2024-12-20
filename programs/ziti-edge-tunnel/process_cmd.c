// Copyright NetFoundry Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


#include <ziti/ziti_log.h>
#include <ziti/ziti_tunnel_cbs.h>

#include "identity-utils.h"
#include "instance-config.h"

extern char *config_dir;
extern char *config_file;
extern bool uses_config_dir;

#if _WIN32
#include "service-utils.h"
#include "windows/windows-service.h"

#define realpath(rel, abs) _fullpath(abs, rel, MAX_PATH)
#endif

void free_add_id_req(struct add_identity_request_s * req) {
    if (req) {
        free(req->identifier);
        free(req->identifier_file_name);
        free(req->jwt_content);
        free(req->url);
        free(req->key);
        free(req->certificate);
        free(req);
    }
}

static void tunnel_enroll_cb(const ziti_config *cfg, int status, const char *err, void *ctx) {
    struct add_identity_request_s *add_id_req = ctx;

    tunnel_result result = {
        .success = false,
        .error = NULL,
        .data = NULL,
        .code = IPC_ERROR,
    };

    FILE *f = add_id_req->add_id_ctx;

    if (status != ZITI_OK) {
        fflush(f);
        fclose(f);
        ZITI_LOG(ERROR, "enrollment failed: %s(%d)", err, status);
        char *e = calloc(1024, sizeof(char));
        sprintf(e, "enrollment failed: %s", err);
        result.error = e;

        if(add_id_req != NULL) {
            add_id_req->cmd_cb(&result, add_id_req->cmd_ctx);
            if(add_id_req->identifier != NULL) {
                ZITI_LOG(ERROR, "removing failed identity file: %s", add_id_req->identifier);
                remove(add_id_req->identifier);
            }
        }
        free(add_id_req);
        free(e);
        return;
    }

    size_t len;
    char *cfg_json = ziti_config_to_json(cfg, 0, &len);

    if (fwrite(cfg_json, 1, len, f) != len) {
        ZITI_LOG(ERROR, "failed to write config file");
        fclose(f);
        result.error = "failed to write config file";
        add_id_req->cmd_cb(&result,  add_id_req->cmd_ctx);
        free_add_id_req(add_id_req);
        return;
    }

    free(cfg_json);
    fflush(f);
    fclose(f);

    create_or_get_tunnel_identity(add_id_req->identifier, add_id_req->identifier_file_name);

    // send load identity command to the controller
    tunnel_load_identity load_identity_options = {
        .identifier = add_id_req->identifier,
        .path = add_id_req->identifier,
        .apiPageSize = get_api_page_size(),
};
    size_t json_len;
    tunnel_command tnl_cmd = {
        .command = TunnelCommand_LoadIdentity,
        .data = tunnel_load_identity_to_json(&load_identity_options, MODEL_JSON_COMPACT, &json_len),
};
    send_tunnel_command(&tnl_cmd, add_id_req->cmd_ctx);
    free_tunnel_command(&tnl_cmd);
    free_add_id_req(add_id_req);
    save_tunnel_status_to_file();
}

static void enroll_ziti_async(uv_loop_t *loop, void *arg) {
    struct add_identity_request_s *add_id_req = arg;

    ziti_enroll_opts enroll_opts = {0};
    enroll_opts.name = add_id_req->identifier;
    enroll_opts.token = add_id_req->jwt_content;
    enroll_opts.use_keychain = add_id_req->use_keychain;
    enroll_opts.key = add_id_req->key;
    enroll_opts.cert = add_id_req->certificate;
    enroll_opts.url = add_id_req->url;

    int enroll_result = ziti_enroll(&enroll_opts, loop, tunnel_enroll_cb, add_id_req);
    if (enroll_result == ZITI_OK) {
        ZITI_LOG(INFO, "enrollment started. identity file will be written to: %s", add_id_req->identifier);
    } else {
        ZITI_LOG(ERROR, "cannot enroll: %d", enroll_result);
        tunnel_enroll_cb(NULL, ZITI_INVALID_STATE, "enrollment JWT or verifiable controller URL is required", add_id_req);
    }
}

// Function to check if the resultant file path is within the config_dir
bool is_within_config_dir(const char *file_path) {
    char resolved_file_path[PATH_MAX];

    // Resolve the file path
    realpath(file_path, resolved_file_path);

    // Compare if the resolved file path is within the config_dir
    int cmp = strncmp(resolved_file_path, config_dir, strlen(config_dir));
    if (cmp == 0) {
        return true; // File is within the config_dir
    }

    return false;  // File is not within the config_dir
}

bool process_tunnel_commands(const tunnel_command *tnl_cmd, command_cb cb, void *ctx) {
    char dynamic_err[1024];
    tunnel_result result = {
            .success = false,
            .error = NULL,
            .data = NULL,
            .code = IPC_ERROR,
    };
    bool cmd_accepted = false;
    bool cmd_forces_save_file = true;
    switch (tnl_cmd->command) {
        case TunnelCommand_SetLogLevel: {
            cmd_accepted = true;

            tunnel_set_log_level tunnel_set_log_level_cmd = {0};
            if (tnl_cmd->data == NULL ||
                parse_tunnel_set_log_level(&tunnel_set_log_level_cmd, tnl_cmd->data, strlen(tnl_cmd->data)) < 0 ||
                tunnel_set_log_level_cmd.loglevel == NULL) {
                result.error = "invalid command";
                result.success = false;
                break;
            }

            if (strcasecmp(ziti_log_level_label(), tunnel_set_log_level_cmd.loglevel) != 0) {
                ziti_log_set_level_by_label(tunnel_set_log_level_cmd.loglevel);
                ziti_tunnel_set_log_level(get_log_level(tunnel_set_log_level_cmd.loglevel));
                const char *level = ziti_log_level_label();
                set_log_level(level);
                ZITI_LOG(INFO, "Log level is set to %s", level);
            } else {
                ZITI_LOG(INFO, "Log level is already set to %s", tunnel_set_log_level_cmd.loglevel);
            }
            result.success = true;
            result.code = IPC_SUCCESS;

            break;
        }
        case TunnelCommand_UpdateTunIpv4: {
            cmd_accepted = true;

            tunnel_tun_ip_v4 tunnel_tun_ip_v4_cmd = {0};
            if (tnl_cmd->data == NULL || parse_tunnel_tun_ip_v4(&tunnel_tun_ip_v4_cmd, tnl_cmd->data, strlen(tnl_cmd->data)) < 0) {
                result.error = "invalid command";
                result.success = false;
                free_tunnel_tun_ip_v4(&tunnel_tun_ip_v4_cmd);
                break;
            }
            if (tunnel_tun_ip_v4_cmd.prefixLength < MINTUNPREFIXLENGTH || tunnel_tun_ip_v4_cmd.prefixLength > MAXTUNPREFIXLENGTH) {
                result.error = "prefix length should be between 10 and 18";
                result.success = false;
                break;
            }
            char* tun_ip_str = strdup(tunnel_tun_ip_v4_cmd.tunIP);
            // make a copy, so we can free it later - validating ip address input
            char* tun_ip_cpy = tun_ip_str;
            char* ip_ptr = strtok(tun_ip_str, "."); //cut the string using dot delimiter
            if (ip_ptr == NULL) {
                result.error = "Invalid IP address";
                result.success = false;
                break;
            }
            int dots = 0;
            bool validationStatus = true;
            while (ip_ptr) {
                bool isInt = true;
                char* ip_str = ip_ptr;
                while (*ip_str) {
                    if(!isdigit(*ip_str)){ //if the character is not a number, break
                        isInt = false;
                        validationStatus = false;
                        break;
                    }
                    ip_str++; //point to next character
                }
                if (!isInt) {
                    break;
                }
                int num = atoi(ip_ptr); //convert substring to number
                if (num >= 0 && num <= 255) {
                    ip_ptr = strtok(NULL, "."); //cut the next part of the string
                    if (ip_ptr != NULL)
                        dots++; //increase the dot count
                } else {
                    validationStatus = false;
                    break;
                }
            }
            free(tun_ip_cpy);
            if (dots != 3 || !validationStatus) {
                result.error = "Invalid IP address";
                result.success = false;
                free_tunnel_tun_ip_v4(&tunnel_tun_ip_v4_cmd);
                break;
            }
            if (tunnel_tun_ip_v4_cmd.tunIP == NULL) {
                result.error = "Tun IP is null";
                result.success = false;
                free_tunnel_tun_ip_v4(&tunnel_tun_ip_v4_cmd);
                break;
            }
            set_tun_ipv4_into_instance(tunnel_tun_ip_v4_cmd.tunIP,
                                       (int)tunnel_tun_ip_v4_cmd.prefixLength,
                                       tunnel_tun_ip_v4_cmd.addDns);
            result.success = true;
            result.code = IPC_SUCCESS;
            break;
        }
        case TunnelCommand_Status: {
            cmd_accepted = true;
            cmd_forces_save_file = false;
            tunnel_status* status = get_tunnel_status();
            result.success = true;
            result.code = IPC_SUCCESS;
            size_t json_len;
            result.data = tunnel_status_to_json(status, MODEL_JSON_COMPACT, &json_len);
            break;
        }

        case TunnelCommand_AddIdentity : {
            cmd_accepted = true;
            if (tnl_cmd->data == NULL) {
                result.error = "invalid command";
                result.success = false;
                break;
            }

            if (!uses_config_dir) {
                result.error = "config directory not set, add command requires an identity-dir";
                result.success = false;
                break;
            }

            tunnel_add_identity tunnel_add_identity_cmd = {0};
            int parse_result = parse_tunnel_add_identity(&tunnel_add_identity_cmd, tnl_cmd->data, strlen(tnl_cmd->data));

            if (parse_result < 0) {
                result.error = "invalid command - could not parse";
                result.success = false;
                free_tunnel_add_identity(&tunnel_add_identity_cmd);
                break;
            }
            bool is_jwt = tunnel_add_identity_cmd.identityFilename != NULL || tunnel_add_identity_cmd.jwtContent != NULL;
            bool is_url = tunnel_add_identity_cmd.controllerURL != NULL;
            bool is_3rd_party_ca = tunnel_add_identity_cmd.cert != NULL || tunnel_add_identity_cmd.key != NULL;
            bool enrollment_methods_supplied = is_jwt || is_url;

            if (!enrollment_methods_supplied) {
                result.error = "no enrollment options detected. either JWT or URL must be specified.";
                result.success = false;
                free_tunnel_add_identity(&tunnel_add_identity_cmd);
                break;
            }

            char new_identifier_with_ext[FILENAME_MAX] = {0};
            char new_identifier_path[FILENAME_MAX] = {0};
            if(is_jwt) {
                if (tunnel_add_identity_cmd.identityFilename == NULL) {
                    result.error = "identity filename not provided";
                    result.success = false;
                    break;
                }

                if ((strlen(config_dir) + strlen(tunnel_add_identity_cmd.identityFilename) + 6 /* 6 == ".json\0" */) >= FILENAME_MAX) {
                    ZITI_LOG(ERROR, "failed to identity file: %s%c%s.json, The file name is longer than the max allowed: %d", config_file, PATH_SEP, tunnel_add_identity_cmd.identityFilename, FILENAME_MAX);
                    result.error = "invalid file name";
                    result.success = false;
                    free_tunnel_add_identity(&tunnel_add_identity_cmd);
                    break;
                }
            } else if (is_3rd_party_ca) {
                if (tunnel_add_identity_cmd.cert == NULL) {
                    result.error = "certificate content not provided";
                    result.success = false;
                    free_tunnel_add_identity(&tunnel_add_identity_cmd);
                    break;
                }
                if (tunnel_add_identity_cmd.key == NULL) {
                    result.error = "key content not provided";
                    result.success = false;
                    free_tunnel_add_identity(&tunnel_add_identity_cmd);
                    break;
                }
            } else if (is_url) {
                // empty on purpose for now
            } else {
                result.error = "programming error. this case should not be hit. please file an issue";
                result.success = false;
                free_tunnel_add_identity(&tunnel_add_identity_cmd);
                break;
            }

            snprintf(new_identifier_with_ext, PATH_MAX, "%s.json", tunnel_add_identity_cmd.identityFilename);
            snprintf(new_identifier_path, PATH_MAX, "%s%c%s", config_dir, PATH_SEP, new_identifier_with_ext);

            //verify the resolved file is within the config_dir
            if (!is_within_config_dir(new_identifier_path)) {
                result.error = "identity file invalid. not within the configuration directory";
                result.success = false;
                free_tunnel_add_identity(&tunnel_add_identity_cmd);
                break;
            }

            normalize_identifier(new_identifier_path);

            struct stat file_exists;
            if (stat(new_identifier_path, &file_exists) == 0) {
                snprintf(dynamic_err, sizeof(dynamic_err), "identity exists with the same name: %s", tunnel_add_identity_cmd.identityFilename);
                result.error = dynamic_err;
                result.success = false;
                free_tunnel_add_identity(&tunnel_add_identity_cmd);
                break;
            }

            FILE *outfile;
            if ((outfile = fopen(new_identifier_path, "wb")) == NULL) {
                ZITI_LOG(ERROR, "failed to open file %s: %s(%d)", new_identifier_path, strerror(errno), errno);
                result.error = "invalid file name";
                result.success = false;
                free_tunnel_add_identity(&tunnel_add_identity_cmd);
                break;
            }

#define s_dup(s) ((s) ? strdup(s) : NULL)
            struct add_identity_request_s *add_id_req = calloc(1, sizeof(struct add_identity_request_s));
            add_id_req->cmd_ctx = ctx;
            add_id_req->cmd_cb = cb;
            add_id_req->add_id_ctx = outfile;
            add_id_req->identifier = strdup(new_identifier_path);
            add_id_req->identifier_file_name = strdup(new_identifier_with_ext);
            add_id_req->jwt_content = s_dup(tunnel_add_identity_cmd.jwtContent);
            add_id_req->use_keychain = tunnel_add_identity_cmd.useKeychain;
            add_id_req->key = s_dup(tunnel_add_identity_cmd.key);
            add_id_req->certificate = s_dup(tunnel_add_identity_cmd.cert);
            add_id_req->url = s_dup(tunnel_add_identity_cmd.controllerURL);

            enroll_ziti_async(global_loop_ref, add_id_req);
            free_tunnel_add_identity(&tunnel_add_identity_cmd);
            return true; // do not break here. add_id_req->cmd_cb will respond with success/fail when executed
        }
#if _WIN32
        case TunnelCommand_ServiceControl: {
            cmd_accepted = true;
            tunnel_service_control tunnel_service_control_opts = {0};
            if (tnl_cmd->data == NULL ||
                parse_tunnel_service_control(&tunnel_service_control_opts, tnl_cmd->data, strlen(tnl_cmd->data)) < 0) {
                result.error = "invalid command";
                result.success = false;
                free_tunnel_service_control(&tunnel_service_control_opts);
                break;
            }
            result.success = true;
            result.code = IPC_SUCCESS;
            if (tunnel_service_control_opts.operation != NULL && strcmp(tunnel_service_control_opts.operation, "stop") == 0) {
                // stops the windows service in scm
                if (!stop_windows_service()) {
                    ZITI_LOG(INFO, "Could not send stop signal to scm, Tunnel must not be started as service");
                    stop_tunnel_and_cleanup();
                    uv_stop(global_loop_ref);
                }
            }
            free_tunnel_service_control(&tunnel_service_control_opts);
            break;
        }
        case TunnelCommand_StatusChange: {
            cmd_accepted = true;
            tunnel_status_change tunnel_status_change_opts = {0};
            if (tnl_cmd->data == NULL ||
                parse_tunnel_status_change(&tunnel_status_change_opts, tnl_cmd->data, strlen(tnl_cmd->data)) < 0) {
                result.error = "invalid command";
                result.success = false;
                free_tunnel_status_change(&tunnel_status_change_opts);
                break;
            }
            result.success = true;
            result.code = IPC_SUCCESS;

            endpoint_status_change(tunnel_status_change_opts.woken, tunnel_status_change_opts.unlocked);

            free_tunnel_status_change(&tunnel_status_change_opts);
        }
#endif
        case TunnelCommand_Unknown:
        case TunnelCommand_ZitiDump:
        case TunnelCommand_IpDump:
        case TunnelCommand_LoadIdentity:
        case TunnelCommand_ListIdentities:
        case TunnelCommand_IdentityOnOff:
        case TunnelCommand_EnableMFA:
        case TunnelCommand_SubmitMFA:
        case TunnelCommand_VerifyMFA:
        case TunnelCommand_RemoveMFA:
        case TunnelCommand_GenerateMFACodes:
        case TunnelCommand_GetMFACodes:
        case TunnelCommand_GetMetrics:
        case TunnelCommand_RefreshIdentity:
        case TunnelCommand_RemoveIdentity:
        case TunnelCommand_Enroll:
        case TunnelCommand_ExternalAuth:
        case TunnelCommand_SetUpstreamDNS:
            ZITI_LOG(DEBUG, "command not implemented: %d", tnl_cmd->command);
            break;
    }
    if (cmd_accepted) {
        cb(&result, ctx);
        if (result.success) {
            // should be the last line in this function as it calls the mutex/lock
            if(cmd_forces_save_file) {
                save_tunnel_status_to_file();
            }
        }
        if (result.data) {
            free(result.data);
        }
        return true;
    } else {
        return false;
    }
}
