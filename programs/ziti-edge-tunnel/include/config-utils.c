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

#include <stdio.h>
#include <stdlib.h>
#include "string.h"

const char* app_data = "APPDATA";

char* get_system_config_path() {
    char* config_path = malloc(FILENAME_MAX * sizeof(char));
#if _WIN32
    sprintf(config_path, "%s/NetFoundry", getenv(app_data));
#else
    sprintf(config_path, "%s", "/tmp");
#endif
    return config_path;
}

char* get_config_file_name(char* config_path) {
    char* config_file_name = calloc(FILENAME_MAX, sizeof(char));
    if (config_path != NULL) {
        snprintf(config_file_name, FILENAME_MAX, "%s/config.json", config_path);
        return config_file_name;
    } else {
        return "config.json";
    }

}

char* get_backup_config_file_name(char* config_path) {
    char* bkp_config_file_name = calloc(FILENAME_MAX, sizeof(char));
    if (config_path != NULL) {
        snprintf(bkp_config_file_name, FILENAME_MAX, "%s/config.json.backup", config_path);
        return bkp_config_file_name;
    } else {
        return "config.json.backup";
    }
}

