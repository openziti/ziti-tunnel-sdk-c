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

#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ziti/ziti_log.h>

int run_command_va(bool log_nonzero_ec, const char* cmd, va_list args) {
    char cmdline[1024];
    vsprintf(cmdline, cmd, args);

    int rc = system(cmdline);
    if (rc != 0 && log_nonzero_ec) {
        ZITI_LOG(ERROR, "cmd{%s} failed: %d/%d/%s\n", cmdline, rc, errno, strerror(errno));
    }
    ZITI_LOG(DEBUG, "system(%s) returned %d", cmdline, rc);
    return WEXITSTATUS(rc);
}

int run_command(const char *cmd, ...) {
    va_list args;
    va_start(args, cmd);
    int r = run_command_va(true, cmd, args);
    va_end(args);
    return r;
}

int run_command_ex(bool log_nonzero_ec, const char *cmd, ...) {
    va_list args;
    va_start(args, cmd);
    int r = run_command_va(log_nonzero_ec, cmd, args);
    va_end(args);
    return r;
}
