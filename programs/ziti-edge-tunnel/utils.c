#include <stdio.h>
#include <stdlib.h>

const char* app_data = "APPDATA";

char* get_system_config_path() {
    char* config_path = malloc(FILENAME_MAX * sizeof(char));
    sprintf(config_path, "%s/NetFoundry", getenv(app_data));

    return config_path;
}

