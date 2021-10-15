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

#ifndef ZITI_TUNNEL_SDK_C_FILE_ROTATOR_H
#define ZITI_TUNNEL_SDK_C_FILE_ROTATOR_H

bool open_log(char* log_filename);
void close_log();
void rotate_log();
void stop_log_check();
struct tm* get_log_start_time();
char* get_log_file_name();

bool log_init(uv_loop_t *, bool);
void ziti_log_writer(int , const char *, const char *, size_t);

#endif //ZITI_TUNNEL_SDK_C_FILE_ROTATOR_H
