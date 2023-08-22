/*
 Copyright 2021 NetFoundry Inc.

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
#include <stdbool.h>
#include <stdio.h>
#include <pwd.h>
#ifdef HAVE_LIBCAP_H
#include <sys/capability.h>
#endif

int run_command_va(bool log_nonzero_ec, const char* cmd, va_list args);
int run_command(const char *cmd, ...);
int run_command_ex(bool log_nonzero_ec, const char *cmd, ...);
bool is_executable(const char *path);
bool is_symlink(const char *path);
uid_t get_user_uid(const char *username);
#ifdef HAVE_LIBCAP_H
bool has_effective_capability(cap_value_t cap);
#endif
