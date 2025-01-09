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

#include <windows.h>
#include <dbghelp.h>
#include <stdio.h>

extern char* get_log_path();
LONG WINAPI CrashFilter(EXCEPTION_POINTERS *pExceptionInfo) {
    char* mini_dump_path = calloc(MAX_PATH, sizeof(char));
    snprintf(mini_dump_path, MAX_PATH, "%s%cziti-edge-tunnel.crash.dmp", get_log_path(), PATH_SEP);

    printf("minidump created at: %s", mini_dump_path);
    HANDLE hFile = CreateFile(mini_dump_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile && hFile != INVALID_HANDLE_VALUE) {
        MINIDUMP_EXCEPTION_INFORMATION mei = {
                GetCurrentThreadId(),
                pExceptionInfo,
                TRUE
        };
        MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hFile, MiniDumpWithThreadInfo, &mei, NULL, NULL);
        CloseHandle(hFile);
    }
    free(mini_dump_path);
    mini_dump_path = NULL;
    return EXCEPTION_EXECUTE_HANDLER;
}