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
#include <pwd.h>
#ifdef HAVE_LIBCAP_PKG
#include <sys/capability.h>
#endif
#include <sys/stat.h>
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

bool is_executable(const char *path) {
    struct stat s;
    return (stat(path, &s) == 0 && (s.st_mode & S_IXUSR));
}

bool is_symlink(const char *path) {
    struct stat s;
    return (lstat(path, &s) == 0 && S_ISLNK(s.st_mode));
}

#ifdef HAVE_LIBCAP_PKG
bool has_effective_capability(cap_value_t cap) {
    cap_t caps;
    cap_flag_value_t flag;

    caps = cap_get_proc();

    if (caps == NULL) {
        ZITI_LOG(ERROR, "could not get process capabilities: %d/%s", errno, strerror(errno));
        return false;
    }

    if (cap_get_flag(caps, cap, CAP_EFFECTIVE, &flag) == -1) {
        ZITI_LOG(ERROR, "could not get capability flags: %d/%s", errno, strerror(errno));
        cap_free(caps);
        return false;
    }

    if (flag != CAP_SET) {
        char *cap_name = cap_to_name(cap);
        if (cap_name == NULL) {
            ZITI_LOG(ERROR, "failure getting capability name");
        } else {
            ZITI_LOG(WARN, "capability %s is missing", cap_name);
            cap_free(cap_name);
        }
        cap_free(caps);
        return false;
    }

    cap_free(caps);
    return true;
}
#endif

uid_t get_user_uid(const char *username) {
    uid_t ziti_uid = -1;

    struct passwd *pwd = getpwnam(username);
    if (pwd == NULL) {
        ZITI_LOG(ERROR, "could not find id of '%s' user\n", username);
        return ziti_uid;
    }

    ziti_uid = pwd->pw_uid;
    ZITI_LOG(TRACE, "found uid=%d for user '%s'\n", ziti_uid, username);
    return ziti_uid;
}
