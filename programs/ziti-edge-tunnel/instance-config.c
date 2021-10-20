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

bool load_tunnel_status_from_file() {
    char* config_path = get_system_config_path();

    int check = mkdir(config_path);
    if (check == 0) {
        ZITI_LOG(TRACE,"config path is created at %s", config_path);
    } else {
        ZITI_LOG(TRACE,"config path is found at %s", config_path);
    }
    bool loaded = false;

    char* config_file_name = calloc(FILENAME_MAX, sizeof(char));
    char* bkp_config_file_name = calloc(FILENAME_MAX, sizeof(char));

    // try to load tunnel status from config file
    snprintf(config_file_name, FILENAME_MAX, "%s/config.json", config_path);
    loaded = load_config_from_file(config_file_name);

    // try to load tunnel status from backup config file
    if (!loaded) {
        snprintf(bkp_config_file_name, FILENAME_MAX, "%s/config.json.backup", config_path);
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

        char* config_file_name = calloc(FILENAME_MAX, sizeof(char));
        char* bkp_config_file_name = calloc(FILENAME_MAX, sizeof(char));
        snprintf(config_file_name, FILENAME_MAX, "%s/config.json", config_path);
        snprintf(bkp_config_file_name, FILENAME_MAX, "%s/config.json.backup", config_path);

        //copy config to backup file
        FILE* config = fopen(config_file_name, "r");
        if (config == NULL) {
            ZITI_LOG(ERROR, "Could not open config file %s", config_file_name);
        } else {
            FILE* backup_config = fopen(bkp_config_file_name, "w");
            if (backup_config == NULL) {
                ZITI_LOG(ERROR, "Could not create backup config file %s", bkp_config_file_name);
            } else {
                char buffer[MIN_BUFFER_LEN];
                while (fread(buffer, 1, MIN_BUFFER_LEN, config) != NULL) {
                    fwrite(buffer, 1, strlen(buffer), backup_config);
                }

                fclose(backup_config);
            }
            fclose(config);
        }

        // write tunnel status to the config file
        config = fopen(config_file_name, "w");
        if (config == NULL) {
            ZITI_LOG(ERROR, "Could not open config file %s to store the tunnel status data", config_file_name);
        } else {
            char* tunnel_status_data = tunnel_status;
            for (int i =0; i< json_len; i=i+MIN_BUFFER_LEN, tunnel_status_data=tunnel_status_data+MIN_BUFFER_LEN) {
                char buffer[MIN_BUFFER_LEN];
                snprintf(buffer, MIN_BUFFER_LEN,"%s", tunnel_status_data);
                fwrite(buffer, 1, strlen(buffer), config);
            }
            saved = true;
            fclose(config);
        }

        free(config_file_name);
        free(config_path);
   }
    free(tunnel_status);
    return saved;
}
