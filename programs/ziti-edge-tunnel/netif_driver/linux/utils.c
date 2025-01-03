/*
 Copyright NetFoundry Inc.

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
#include <sys/stat.h>
#include <ziti/ziti_log.h>

int run_command_va(bool log_nonzero_ec, const char* cmd, va_list args) {
    char cmdline[1024];
    vsnprintf(cmdline, sizeof(cmdline), cmd, args);

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

struct queued_command_s {
    char *cmdline;
    int exitcode;
};

static void do_queued_command(uv_work_t *wr) {
    struct queued_command_s *qcmd = wr->data;
    ZITI_LOG(DEBUG, "running '%s'", qcmd->cmdline);
    qcmd->exitcode = system(qcmd->cmdline);
    ZITI_LOG(DEBUG, "system(%s) returned %d", qcmd->cmdline, qcmd->exitcode);
}

static void default_after_queued_command(uv_work_t *wr, int status) {
    struct queued_command_s *qcmd = wr->data;
    free(qcmd->cmdline);
    free(qcmd);
    free(wr);
}

int queue_command_va(uv_after_work_cb after, const char *cmd, va_list args) {
    uv_work_t *wr = calloc(1, sizeof(uv_work_t));
    struct queued_command_s *qcmd = calloc(1, sizeof(struct queued_command_s));
    wr->data = qcmd;
    vasprintf(&qcmd->cmdline, cmd, args);
    return uv_queue_work(uv_default_loop(), wr, do_queued_command, after);
}

int queue_command(const char *cmd, ...) {
    va_list args;
    va_start(args, cmd);
    int r = queue_command_va(default_after_queued_command, cmd, args);
    va_end(args);
    return r;
}

int queue_command_ex(uv_after_work_cb after, const char *cmd, ...) {
    va_list args;
    va_start(args, cmd);
    int r = queue_command_va(after, cmd, args);
    va_end(args);
    return r;
}

bool is_executable(const char *path) {
    struct stat s;
    return (stat(path, &s) == 0 && (s.st_mode & S_IXUSR));
}

bool is_symlink(const char *path) {
    struct stat s;
    return (lstat(path, &s) == 0 && S_ISLNK(s.st_mode));
}
