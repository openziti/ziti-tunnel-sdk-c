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

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ziti/ziti_log.h>
#include <time.h>
#include <log-utils.h>
#if _WIN32
#include "windows/windows-service.h"
#include "windows/windows-scripts.h"
#include <direct.h>
#endif

static void delete_older_logs(uv_async_t *ar);

static FILE *ziti_tunneler_log = NULL;
static uv_check_t *log_flusher;
static struct tm *start_time;
char* log_filename;
static bool multi_writer = false;
static const char* log_filename_base = "ziti-tunneler.log";
static int rotation_count = 7;

static char* get_log_path() {
    char process_dir[FILENAME_MAX]; //create string buffer to hold path
#if _WIN32
    char process_full_path[FILENAME_MAX];
    char drive[_MAX_DRIVE];
    char dir[_MAX_DIR];
    get_process_path(process_full_path, FILENAME_MAX);
    _splitpath_s(process_full_path, drive, sizeof(drive), dir, sizeof(dir), NULL, 0, NULL, 0);
    _makepath_s(process_dir, sizeof(process_dir), drive, dir, NULL, NULL);
#else
    sprintf(process_dir, "/tmp");
#endif

    char* log_path = calloc(FILENAME_MAX, sizeof(char));
    snprintf(log_path, FILENAME_MAX, "%s/logs", process_dir);
    int check;
#if _WIN32
    mkdir(log_path);
    strcat(log_path, "/service");
    check = mkdir(log_path);
#else
    mkdir(log_path, 0755);
#endif
    if (check == 0) {
        printf("\nlog path is created at %s", log_path);
    } else {
        printf("\nlog path is found at %s", log_path);
    }
    return log_path;
}

char* get_base_filename() {
    char* log_path = get_log_path();
    char* temp_log_filename = calloc(FILENAME_MAX, sizeof(char));
    snprintf(temp_log_filename, FILENAME_MAX, "%s/%s", log_path, log_filename_base);
    free(log_path);
    return temp_log_filename;
}

static char* create_log_filename() {
    char* base_log_filename = get_base_filename();

    char time_val[32];
    strftime(time_val, sizeof(time_val), "%Y%m%d0000", start_time);

    char* temp_log_filename = calloc(FILENAME_MAX, sizeof(char));
    sprintf(temp_log_filename, "%s.%s.log", base_log_filename, time_val);
    free(base_log_filename);
    return temp_log_filename;
}

void update_symlink_async(uv_async_t *ar) {
    uv_loop_t *symlink_loop = ar->loop;

    uv_close((uv_handle_t *) ar, (uv_close_cb) free);

    update_symlink(symlink_loop, get_base_filename(), log_filename);
}

void flush_log(uv_check_t *handle) {
    if (ziti_tunneler_log != NULL) {
        fflush(ziti_tunneler_log);
    }
    if (multi_writer) {
        fflush(stdout);
    }

    uv_timeval64_t now;
    uv_gettimeofday(&now);
    struct tm *tm = gmtime(&now.tv_sec);

    if (handle->data) {
        struct tm *orig_time = handle->data;
        if (orig_time->tm_mday < tm->tm_mday) {
            if (rotate_log()) {
#if _WIN32
                uv_async_t *ar = calloc(1, sizeof(uv_async_t));
                uv_async_init(handle->loop, ar, update_symlink_async);
                uv_async_send(ar);
#endif
            }
            handle->data = start_time;
            uv_async_t *ar = calloc(1, sizeof(uv_async_t));
            uv_async_init(handle->loop, ar, delete_older_logs);
            uv_async_send(ar);
        }
    }

}

bool log_init(uv_loop_t *ziti_loop, bool is_multi_writer) {

    uv_timeval64_t file_time;
    uv_gettimeofday(&file_time);
    start_time = calloc(1, sizeof(struct tm));
#if _WIN32
    _gmtime64_s(start_time, &file_time.tv_sec);
#else
    gmtime_r(&file_time.tv_sec, start_time);
#endif

    uv_async_t *ar_delete = calloc(1, sizeof(uv_async_t));
    uv_async_init(ziti_loop, ar_delete, delete_older_logs);
    uv_async_send(ar_delete);

    multi_writer = is_multi_writer;

    log_flusher = calloc(1, sizeof(uv_check_t));
    uv_check_init(ziti_loop, log_flusher);
    log_flusher->data = start_time;
    uv_unref((uv_handle_t *) log_flusher);
    uv_check_start(log_flusher, flush_log);


    log_filename = create_log_filename();

    if (!open_log(log_filename)) {
        return false;
    }
#if _WIN32
    SvcReportEvent(TEXT(log_filename), EVENTLOG_INFORMATION_TYPE);
    uv_async_t *ar_update = calloc(1, sizeof(uv_async_t));
    uv_async_init(ziti_loop, ar_update, update_symlink_async);
    uv_async_send(ar_update);
#endif
    return true;
}

struct tm* get_log_start_time() {
    return start_time;
}

char* get_log_file_name(){
    return log_filename;
}

static const char* parse_level(int level) {
    const char* err_level;
    switch(level) {
        case 0:
            err_level = "FATAL";
            break;
        case 1:
            err_level = "ERROR";
            break;
        case 2:
            err_level = "WARN";
            break;
        case 3:
            err_level = "INFO";
            break;
        case 4:
            err_level = "DEBUG";
            break;
        case 5:
            err_level = "VERBOSE";
            break;
        case 6:
            err_level = "TRACE";
            break;
        default:
            err_level = "UNKNOWN";
    }
    return err_level;
}

void ziti_log_writer(int level, const char *loc, const char *msg, size_t msglen) {
    char curr_time[32];
    uv_timeval64_t now;
    uv_gettimeofday(&now);
    struct tm *tm = gmtime(&now.tv_sec);

    snprintf(curr_time, sizeof(curr_time), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
             1900 + tm->tm_year, tm->tm_mon + 1, tm->tm_mday,
             tm->tm_hour, tm->tm_min, tm->tm_sec, now.tv_usec / 1000
    );

    if ( ziti_tunneler_log != NULL) {
        fprintf(ziti_tunneler_log, "\n[%s] %7s %s ", curr_time, parse_level(level), loc);
        fwrite(msg, 1, msglen, ziti_tunneler_log);
    }

    if(multi_writer) {
        printf("\n[%s] %7s %s %.*s", curr_time, parse_level(level), loc, msglen, msg);
    }

}

bool open_log(char* filename) {
    if((ziti_tunneler_log=fopen(filename,"a")) == NULL) {
        printf("Could not open logs file %s, due to %s", filename, strerror(errno));
        return false;
    }
    return true;
}

void close_log() {
    if (ziti_tunneler_log != NULL) {
        fclose(ziti_tunneler_log);
        ziti_tunneler_log = NULL;
    }
    if (log_filename != NULL) {
        free(log_filename);
        log_filename = NULL;
    }
}

void stop_log_check() {
    if (log_flusher != NULL) {
        uv_check_stop(log_flusher);
        free(log_flusher->data);
        free(log_flusher);
        log_flusher = NULL;
    }
}

bool rotate_log() {
    close_log();

    uv_timeval64_t file_time;
    uv_gettimeofday(&file_time);
    if (start_time) {
        free(start_time);
        start_time = NULL;
    }
    start_time = calloc(1, sizeof(struct tm));
#if _WIN32
    _gmtime64_s(start_time, &file_time.tv_sec);
#else
    gmtime_r(&file_time.tv_sec, start_time);
#endif
    log_filename = create_log_filename();

    if (open_log(log_filename)) {
        return true;
    } else {
        return false;
    }
}

static void delete_older_logs(uv_async_t *ar) {
    uv_loop_t *symlink_loop = ar->loop;

    uv_close((uv_handle_t *) ar, (uv_close_cb) free);

    char* log_path = get_log_path();

    uv_fs_t fs;
    int rc = uv_fs_scandir(symlink_loop, &fs, log_path, 0, NULL);
    // we wanted to retain last 7 days logs, so this function will return, if there are less than or equal to 7 elements in this folder
    // if there are more than 7 files/folder, it will continue. Only files starting with the given log base file name will be considered while cleaning up
    if (rc <= 7) {
        if (rc < 0) {
            ZITI_LOG(ERROR, "failed to scan dir[%s]: %d/%s", log_path, rc, uv_strerror(rc));
        } else {
            ZITI_LOG(TRACE, "Files count in [%s] is %d, not deleting log files.", log_path, rc);
            uv_fs_req_cleanup(&fs);
        }
        free(log_path);
        return;
    }

    char **log_files = calloc(rc + 1 , sizeof(char *));
    uv_dirent_t file;
    int rotation_cnt = 0;
    while (uv_fs_scandir_next(&fs, &file) == 0) {
        ZITI_LOG(TRACE, "file/folder in %s = %s %d", log_path, file.name, file.type);

        if (file.type == UV_DIRENT_FILE) {
            if (strncmp(file.name, log_filename_base, strlen(log_filename_base)) == 0) {
                log_files[rotation_cnt] = strdup(file.name);
                rotation_cnt++;
            }
        }
    }

    int rotation_index = rotation_cnt;
    while (rotation_index > rotation_count) {
        char *old_log = NULL;
        int old_idx = -1;

        for(int idx =0; idx < rotation_cnt; idx++) {
            if (old_log == NULL && log_files[idx]) {
                old_log = log_files[idx];
                old_idx = idx;
                continue;
            }
            if (old_log == NULL) {
                continue;
            }
            if (strcmp(old_log, log_files[idx]) > 0 ) {
                old_log = log_files[idx];
                old_idx = idx;
            }
        }
        if (old_log != NULL) {
            char logfile_to_delete[MAXPATHLEN];
            snprintf(logfile_to_delete, MAXPATHLEN, "%s/%s", log_path, old_log);
            ZITI_LOG(INFO, "Deleting old log file %s", logfile_to_delete);
            remove(logfile_to_delete);
            rotation_index--;
            free (old_log);
            old_log = NULL;
            log_files[old_idx] = NULL;
        }
    }

    // clean up resources
    uv_fs_req_cleanup(&fs);
    for(int idx =0; idx < rotation_cnt; idx++){
        // older files are already deleted and free'd
        if (log_files[idx]) {
            free(log_files[idx]);
        }
    }
    free(log_path);
    free(log_files);
}
