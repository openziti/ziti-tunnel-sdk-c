// Copyright 2024 NetFoundry Inc.
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

static void tunnel_enroll_cb(const ziti_config *cfg, int status, const char *err, void *ctx) {
    struct add_identity_request_s *add_id_req = ctx;

    tunnel_result result = {
        .success = false,
        .error = NULL,
        .data = NULL,
        .code = IPC_ERROR,
};

    if (status != ZITI_OK) {
        ZITI_LOG(ERROR, "enrollment failed: %s(%d)", err, status);
        result.error = "enrollment failed";
        add_id_req->cmd_cb(&result, add_id_req->cmd_ctx);
        free(add_id_req);
        return;
    }

    FILE *f = add_id_req->add_id_ctx;

    size_t len;
    char *cfg_json = ziti_config_to_json(cfg, 0, &len);

    if (fwrite(cfg_json, 1, len, f) != len) {
        ZITI_LOG(ERROR, "failed to write config file");
        fclose(f);
        result.error = "failed to write config file";
        add_id_req->cmd_cb(&result,  add_id_req->cmd_ctx);
        free(add_id_req);
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
    free(add_id_req);
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

    ziti_enroll(&enroll_opts, loop, tunnel_enroll_cb, add_id_req);
}

bool process_tunnel_commands(const tunnel_command *tnl_cmd, command_cb cb, void *ctx) {
    tunnel_result result = {
            .success = false,
            .error = NULL,
            .data = NULL,
            .code = IPC_ERROR,
    };
    bool cmd_accepted = false;
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
            tunnel_status* status = get_tunnel_status();
            result.success = true;
            result.code = IPC_SUCCESS;
            size_t json_len;
            result.data = tunnel_status_to_json(status, MODEL_JSON_COMPACT, &json_len);
            break;
        }

        case TunnelCommand_AddIdentity : {
            cmd_accepted = true;
            tunnel_add_identity tunnel_add_identity_cmd = {0};
            if (tnl_cmd->data == NULL ||
                parse_tunnel_add_identity(&tunnel_add_identity_cmd, tnl_cmd->data, strlen(tnl_cmd->data)) < 0 ||
                (tunnel_add_identity_cmd.jwtFileName == NULL && tunnel_add_identity_cmd.jwtContent == NULL)) {
                result.error = "invalid command";
                result.success = false;
                free_tunnel_add_identity(&tunnel_add_identity_cmd);
                break;
            }

            if (tunnel_add_identity_cmd.jwtFileName == NULL) {
                result.error = "identity filename not provided";
                result.success = false;
                break;
            }

            if (tunnel_add_identity_cmd.jwtContent == NULL) {
                result.error = "jwt content not provided";
                result.success = false;
                break;
            }

            if (config_dir == NULL) {
                result.error = "config directory not set";
                result.success = false;
                break;
            }

            char* extension = strstr(tunnel_add_identity_cmd.jwtFileName, ".jwt");
            size_t length;
            if (extension != NULL) {
                length = extension - tunnel_add_identity_cmd.jwtFileName;
            } else {
                length = strlen(tunnel_add_identity_cmd.jwtFileName);
            }
            char new_identifier[FILENAME_MAX] = {0};
            char new_identifier_name[FILENAME_MAX] = {0};
            if ((strlen(config_dir) + length + 6) >  FILENAME_MAX - 1 ) {
                ZITI_LOG(ERROR, "failed to create file %s%c%s.json, The length of the file name is longer than %d", config_dir, PATH_SEP, tunnel_add_identity_cmd.jwtFileName, FILENAME_MAX);
                result.error = "invalid file name";
                result.success = false;
                free_tunnel_add_identity(&tunnel_add_identity_cmd);
                break;
            }
            strncpy(new_identifier_name, tunnel_add_identity_cmd.jwtFileName, length);
            snprintf(new_identifier, FILENAME_MAX, "%s%c%s.json", config_dir, PATH_SEP, new_identifier_name);
            FILE *outfile;
            if ((outfile = fopen(new_identifier, "wb")) == NULL) {
                ZITI_LOG(ERROR, "failed to open file %s: %s(%d)", new_identifier, strerror(errno), errno);
                result.error = "invalid file name";
                result.success = false;
                free_tunnel_add_identity(&tunnel_add_identity_cmd);
                break;
            }

            struct add_identity_request_s *add_id_req = calloc(1, sizeof(struct add_identity_request_s));
            add_id_req->cmd_ctx = ctx;
            add_id_req->cmd_cb = cb;
            add_id_req->add_id_ctx = outfile;
            add_id_req->identifier = strdup(new_identifier);
            add_id_req->identifier_file_name = strdup(new_identifier_name);
            add_id_req->jwt_content = strdup(tunnel_add_identity_cmd.jwtContent);
            add_id_req->use_keychain = tunnel_add_identity_cmd.useKeychain;
            add_id_req->key = strdup(tunnel_add_identity_cmd.key);
            add_id_req->certificate = strdup(tunnel_add_identity_cmd.cert);
            add_id_req->url = strdup(tunnel_add_identity_cmd.controllerURL);

            enroll_ziti_async(global_loop_ref, add_id_req);
            free_tunnel_add_identity(&tunnel_add_identity_cmd);
            return true;
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
    }
    if (cmd_accepted) {
        cb(&result, ctx);
        if (result.success) {
            // should be the last line in this function as it calls the mutex/lock
            save_tunnel_status_to_file();
        }
        if (result.data) {
            free(result.data);
        }
        return true;
    } else {
        return false;
    }
}
