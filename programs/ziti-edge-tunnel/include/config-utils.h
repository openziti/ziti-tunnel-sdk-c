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

#ifndef ZITI_TUNNEL_SDK_C_CONFIG_UTILS_H
#define ZITI_TUNNEL_SDK_C_CONFIG_UTILS_H

char* get_system_config_path();
void set_identifier_path(char* id_dir);
char* get_identifier_path();
char* get_config_file_name(char* config_path);
char* get_backup_config_file_name(char* config_path);

#endif //ZITI_TUNNEL_SDK_C_CONFIG_UTILS_H
