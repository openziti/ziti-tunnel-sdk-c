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

#include "instance-config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "instance.h"
#include <ziti/ziti_log.h>

#if _WIN32
#define realpath(rel, abs) _fullpath(abs, rel, MAX_PATH)
#endif

// to store the whole tunnel status data
#define MIN_BUFFER_LEN 512

static uv_sem_t sem;
static unsigned int sem_value = 1;
static int sem_initialized = -1;

static char* config_dir = NULL;
static bool config_saving_enabled = true;

///
/// \param path represents the location of the configuration to be used
void initialize_instance_config(const char* path) {
    if (!path) {
        //indicates this was started with -i (not -I). Operations should not do anything in this case
        return;
    }

    char actual_config_dir[FILENAME_MAX];
    realpath(path, actual_config_dir);

    config_dir = strdup(actual_config_dir); //save the location of the config dir
    sem_initialized = uv_sem_init(&sem, sem_value);
    if (sem_initialized < 0) {
        ZITI_LOG(WARN, "Could not initialize lock for the config, config file may not be updated");
    }
}

bool load_config_from_file(char* config_file_name) {
    bool loaded = false;

    FILE* config_file = fopen(config_file_name, "r");
    if (config_file != NULL) {
        char* config_buffer = calloc(1024*1024, sizeof(char));
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
        config_buffer[0] = '\0';
        fclose(config_file);
        free(config_buffer);
    } else {
        if (errno != 0) {
            ZITI_LOG(ERROR, "The config file %s cannot be opened due to %s. This is normal if this is a new install or if the config file was removed manually", strerror(errno), config_file_name);
        } else {
            ZITI_LOG(INFO, "The config file %s does not exist. This is normal if this is a new install or if the config file was removed manually", config_file_name);
        }
    }
    return loaded;
}

bool load_tunnel_status_from_file(uv_loop_t* ziti_loop) {
    uv_fs_t fs;
    int check = uv_fs_mkdir(ziti_loop, &fs, config_dir, 0755, NULL);
    if (check == 0) {
        ZITI_LOG(TRACE, "config path is created at %s", config_dir);
    } else if (check == UV_EEXIST) {
        ZITI_LOG(TRACE, "config path exists at %s", config_dir);
    } else {
        ZITI_LOG(ERROR, "error creating %s: %s", config_dir, uv_strerror(check));
        return false;
    }
    bool loaded = false;

    char* config_file_name = get_config_file_name();
    ZITI_LOG(INFO,"Loading config file from %s", config_file_name);

    // try to load tunnel status from config file
    loaded = load_config_from_file(config_file_name);

    // not able to load the tunnel status
    if (!loaded) {
        ZITI_LOG(WARN, "Config file %s cannot be read, does not exist, or is invalid. a new config file will be written if possible.", config_file_name);
    }

    set_config_dir(config_dir);

    free(config_file_name);
    return loaded;
}

bool save_tunnel_status_to_file() {
    if(!config_saving_enabled) {
        ZITI_LOG(DEBUG, "config_saving_enabled is false. not saving config");
        return true;
    }
    if(!config_dir) {
        // no base_dir indicates using -i not -I
        ZITI_LOG(DEBUG, "skipping save_tunnel_status_to_file. config_dir is not set");
        return true;
    }
    size_t json_len;
    char* tunnel_status = get_tunnel_config(&json_len);
    bool saved = false;

    if (json_len > 0) {
        char* config_path = get_system_config_path(config_dir);
        char* config_file_name = get_config_file_name();

        if (sem_initialized == 0) {
            uv_sem_wait(&sem);
        } else {
            ZITI_LOG(ZITI_WTF, "Could not save the config file [%s] due to semaphore lock not initialized error.", config_file_name);
            free(config_file_name);
            free(config_path);
            free(tunnel_status);
            return saved;
        }

        // write tunnel status to the config file
        FILE* config = fopen(config_file_name, "w");
        if (config == NULL) {
            ZITI_LOG(ERROR, "Could not open config file %s to store the tunnel status data", config_file_name);
        } else {
            char* tunnel_status_data = tunnel_status;
            for (int i =0; i< json_len; i=i+MIN_BUFFER_LEN-1, tunnel_status_data=tunnel_status_data+MIN_BUFFER_LEN-1) {
                size_t size = strlen(tunnel_status_data);
                if (size >= MIN_BUFFER_LEN) {
                    size = MIN_BUFFER_LEN - 1;
                }
                char buffer[MIN_BUFFER_LEN] = {0};
                strncpy(buffer, tunnel_status_data, (MIN_BUFFER_LEN-1));
                fwrite(buffer, 1, strlen(buffer), config);
            }
            saved = true;
            fclose(config);
            ZITI_LOG(INFO, "Saved current tunnel status into Config file %s", config_file_name);
        }
        uv_sem_post(&sem);

        free(config_file_name);
        free(config_path);
    }
    free(tunnel_status);
    return saved;
}

void cleanup_instance_config() {
    ZITI_LOG(DEBUG,"Backing up current tunnel status");
    save_tunnel_status_to_file();
    ZITI_LOG(DEBUG,"save_tunnel_status_to_file done ");
    if (sem_initialized == 0) {
        //uv_sem_destroy(&sem);
        ZITI_LOG(DEBUG,"uv_sem_destroy done");
    } else {
        ZITI_LOG(ZITI_WTF, "Could not clean instance config. The semaphore is not initialized.");
    }
}

char* get_config_file_name() {
    if (config_dir != NULL) {
        char* config_file_name = calloc(FILENAME_MAX, sizeof(char));
        snprintf(config_file_name, FILENAME_MAX, "%s%c%s", config_dir, PATH_SEP, DEFAULT_STATE_FILE_NAME);
        normalize_identifier(config_file_name);
        return config_file_name;
    } else {
        return DEFAULT_STATE_FILE_NAME;
    }
}