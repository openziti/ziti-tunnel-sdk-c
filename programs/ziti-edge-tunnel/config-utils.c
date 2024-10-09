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
#include <string.h>
#if __linux__
#include <pwd.h>
#include <unistd.h>
#endif

#if _WIN32
#define realpath(rel, abs) _fullpath(abs, rel, FILENAME_MAX)
#endif

static char* identifier_path = NULL;

char* get_system_config_path(const char* base_dir) {
    char actual_base_path[FILENAME_MAX];
    realpath(base_dir, actual_base_path);

    char* config_path = malloc(FILENAME_MAX * sizeof(char));
#if _WIN32
    snprintf(config_path, FILENAME_MAX, "%s%cNetFoundry", actual_base_path, PATH_SEP);
#elif __linux__
    snprintf(config_path, FILENAME_MAX, "/var/lib/ziti");
#else
    snprintf(config_path, FILENAME_MAX, "/tmp");
#endif
    return config_path;
}

char* get_identifier_path() {
    return identifier_path;
}

void set_identifier_path(char* id_path) {
    if (id_path != NULL) {
        identifier_path = strdup(id_path);
    }
}

