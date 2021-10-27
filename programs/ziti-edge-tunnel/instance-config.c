/*
 Copyright 2019-2020 NetFoundry Inc.

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

#include <stdio.h>
#include <stdlib.h>
#include <config-utils.h>
#include <string.h>
#include <instance.h>
#include <ziti/ziti_log.h>

// to store the whole tunnel status data
#define MAX_BUFFER_LEN 1024 * 1024
#define MIN_BUFFER_LEN 512

static uv_mutex_t mutex;

bool initialize_instance_config() {
    int mutex_init = uv_mutex_init(&mutex);
    if (mutex_init != 0) {
        ZITI_LOG(TRACE, "Could not initialize resources for the config, config file will not be updated");
    }
    return mutex_init;
}

bool load_config_from_file(char* config_file_name) {
    bool loaded = false;

    FILE* config_file = fopen(config_file_name, "r");
    if (config_file != NULL) {
        char *config_buffer = malloc(MAX_BUFFER_LEN * sizeof(char));
        *config_buffer = NULL;
        char line[512];
        while ((fgets(line, sizeof(line), config_file)) != NULL) {
            strcat(config_buffer, line);
        }

        if (strlen(config_buffer) > 0) {
            loaded = load_tunnel_status(config_buffer);
            if (!loaded) {
                ZITI_LOG(WARN, "Config file %s cannot be read, will be overwritten", config_file_name);
            }
        }
        fclose(config_file);
    } else {
        ZITI_LOG(INFO, "The config file %s does not exist. This is normal if this is a new install or if the config file was removed manually", config_file_name);
    }
    return loaded;
}

bool load_tunnel_status_from_file(uv_loop_t* ziti_loop) {
    char* config_path = get_system_config_path();

    uv_fs_t fs;
    int check = uv_fs_mkdir(ziti_loop, &fs, config_path, 0, NULL);
    if (check == 0) {
        ZITI_LOG(TRACE,"config path is created at %s", config_path);
    } else {
        ZITI_LOG(TRACE,"config path is found at %s", config_path);
    }
    bool loaded = false;

    char* config_file_name = get_config_file_name(config_path);
    char* bkp_config_file_name = get_backup_config_file_name(config_path);

    // try to load tunnel status from config file
    loaded = load_config_from_file(config_file_name);

    // try to load tunnel status from backup config file
    if (!loaded) {
        loaded = load_config_from_file(bkp_config_file_name);
    }

    // not able to load the tunnel status from both the config and backup files
    if (!loaded) {
        ZITI_LOG(WARN, "Config files %s and the backup file cannot be read or they do not exist, will create a new config file or the old one will be overwritten", config_file_name);
    }

    free(config_file_name);
    free(bkp_config_file_name);
    free(config_path);
    return loaded;
}

bool save_tunnel_status_to_file() {
    tunnel_status* stat = get_tunnel_status();
    size_t json_len;
    char* tunnel_status = tunnel_status_to_json(stat, 0, &json_len);
    bool saved = false;

    if (json_len > 0) {
        char* config_path = get_system_config_path();

        char* config_file_name = get_config_file_name(config_path);
        char* bkp_config_file_name = get_backup_config_file_name(config_path);

        int stat = uv_mutex_trylock(&mutex);
        if (stat == 0) {
            //copy config to backup file
            FILE* config = fopen(config_file_name, "r");
            if (config == NULL) {
                ZITI_LOG(ERROR, "Could not open config file %s", config_file_name);
            } else {
                FILE* backup_config = fopen(bkp_config_file_name, "w");
                if (backup_config == NULL) {
                    ZITI_LOG(ERROR, "Could not create backup config file %s", bkp_config_file_name);
                } else {
                    while (true) {
                        char buffer[MIN_BUFFER_LEN] = {0};
                        int size = (int) fread(buffer, sizeof(char), MIN_BUFFER_LEN-1, config);
                        if (size <= 0) {
                            break;
                        }
                        fwrite(buffer, sizeof(char), strlen(buffer), backup_config);
                    }

                    fclose(backup_config);
                    ZITI_LOG(TRACE, "Copied Config file to Backup config file %s", bkp_config_file_name);
                }
                fclose(config);
            }

            // write tunnel status to the config file
            config = fopen(config_file_name, "w");
            if (config == NULL) {
                ZITI_LOG(ERROR, "Could not open config file %s to store the tunnel status data", config_file_name);
            } else {
                char* tunnel_status_data = tunnel_status;
                for (int i =0; i< json_len; i=i+MIN_BUFFER_LEN-1, tunnel_status_data=tunnel_status_data+MIN_BUFFER_LEN-1) {
                    char buffer[MIN_BUFFER_LEN] = {0};
                    memcpy(buffer, tunnel_status_data, (MIN_BUFFER_LEN-1));
                    fwrite(buffer, 1, strlen(buffer), config);
                }
                saved = true;
                fclose(config);
                ZITI_LOG(TRACE, "Saved current tunnel status into Config file %s", config_file_name);
            }
            uv_mutex_unlock(&mutex);
            ZITI_LOG(TRACE, "Cleaning up resources used for the backup of tunnel config file %s", config_file_name);
        }
        free(config_file_name);
        free(bkp_config_file_name);
        free(config_path);
   }
    free(tunnel_status);
    return saved;
}

void cleanup_instance_config() {
    ZITI_LOG(TRACE, "Backing up current tunnel status");
    save_tunnel_status_to_file();
    uv_mutex_destroy(&mutex);
}