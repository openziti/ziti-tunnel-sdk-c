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

#include <ctype.h>
#include <string.h>

// must precede anything that pulls in windows.h without winsock2.h first
#include "windows/windows-service.h"

#include <ziti/ziti_log.h>

// the ZDEW installer creates this key and stamps Version with the installed product version
#ifndef INSTALL_REG_ROOT
#define INSTALL_REG_ROOT HKEY_LOCAL_MACHINE
#endif
#ifndef INSTALL_REG_KEY
#define INSTALL_REG_KEY "SOFTWARE\\NetFoundry Inc.\\Ziti Desktop Edge"
#endif
#define INSTALL_REG_VALUE "Version"

#define MAX_VERSION_LEN 64

static char version_buf[MAX_VERSION_LEN + 1];

// key_found distinguishes "try the other registry view" from "the key is here and its value is
// unusable"
static bool read_install_version(REGSAM view, bool *key_found) {
    HKEY key;
    if (RegOpenKeyExA(INSTALL_REG_ROOT, INSTALL_REG_KEY, 0, KEY_READ | view, &key) != ERROR_SUCCESS) {
        return false;
    }
    *key_found = true;

    char buf[MAX_VERSION_LEN + 1];
    DWORD type = 0;
    DWORD len = MAX_VERSION_LEN;
    LSTATUS rc = RegQueryValueExA(key, INSTALL_REG_VALUE, NULL, &type, (LPBYTE) buf, &len);
    RegCloseKey(key);

    if (rc != ERROR_SUCCESS) {
        ZITI_LOG(DEBUG, "could not read %s\\%s: %ld", INSTALL_REG_KEY, INSTALL_REG_VALUE, rc);
        return false;
    }
    if (type != REG_SZ) {
        ZITI_LOG(WARN, "%s\\%s is type %lu, expected REG_SZ", INSTALL_REG_KEY, INSTALL_REG_VALUE, type);
        return false;
    }

    // a registry string is bytes plus a count, so a NUL can sit anywhere: read as a C string it
    // reports the prefix before that NUL, a version that looks real and is not the installed one
    const char *nul = memchr(buf, '\0', len);
    if (nul != NULL && nul != buf + len - 1) {
        ZITI_LOG(WARN, "%s\\%s has an embedded NUL", INSTALL_REG_KEY, INSTALL_REG_VALUE);
        return false;
    }

    // len is the bytes written, and the stored data need not have included a terminator
    buf[len] = '\0';

    // the controller stores whatever it is given
    char *start = buf;
    while (*start != '\0' && isspace((unsigned char) *start)) {
        start++;
    }
    char *end = start + strlen(start);
    while (end > start && isspace((unsigned char) end[-1])) {
        end--;
    }
    *end = '\0';

    if (*start == '\0') {
        ZITI_LOG(WARN, "%s\\%s is empty", INSTALL_REG_KEY, INSTALL_REG_VALUE);
        return false;
    }

    strcpy(version_buf, start);
    return true;
}

const char *installed_app_version(void) {
    // only a successful read writes version_buf, so a failed read would otherwise report whatever
    // an earlier call left behind
    version_buf[0] = '\0';

    // a 32-bit installer package writes the key where a 64-bit read cannot see it
    bool key_found = false;
    if (!read_install_version(KEY_WOW64_64KEY, &key_found) && !key_found) {
        read_install_version(KEY_WOW64_32KEY, &key_found);
    }

    if (version_buf[0] == '\0') {
        // the service need not have come from the installer, so this is not an error
        ZITI_LOG(INFO, "no installed application version found; reporting " APP_VERSION_UNKNOWN);
        return APP_VERSION_UNKNOWN;
    }

    ZITI_LOG(INFO, "reporting installed application version %s", version_buf);
    return version_buf;
}
