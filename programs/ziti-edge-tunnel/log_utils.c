#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <direct.h>
#include <stdbool.h>
#include <ziti/ziti_log.h>
#include <time.h>
#include <file-rotator.h>
#if _WIN32
#include "windows/windows-service.h"
#endif

#define GetCurrentDir _getcwd

#ifndef MAXPATHLEN
#ifdef _MAX_PATH
#define MAXPATHLEN _MAX_PATH
#elif _WIN32
#define MAXPATHLEN 260
#else
#define MAXPATHLEN 4096
#endif
#endif

static FILE *ziti_tunneler_log = NULL;
static uv_check_t *log_flusher;
static struct tm *start_time;
char* log_filename = NULL;
static bool multi_writer = false;
static const char* log_filename_base = "ziti-tunneler.log";
static rotation_count = 7;

static char* get_log_filename() {
    char curr_path[FILENAME_MAX]; //create string buffer to hold path
    GetCurrentDir( curr_path, FILENAME_MAX );

    char log_path[FILENAME_MAX];
    sprintf(log_path, "%s/logs", curr_path);
    int check = mkdir(log_path);
    if (!check) {
        printf("\ncreated log path %s", curr_path);
    } else {
        printf("\nlog path is found %s", curr_path);
    }

    char time_val[32];
    snprintf(time_val, sizeof(time_val), "%04d%02d%02d0000",
             1900 + start_time->tm_year, start_time->tm_mon + 1, start_time->tm_mday
    );

    char* log_filename = malloc(FILENAME_MAX * sizeof(char));
    sprintf(log_filename, "%s/%s.%s", log_path, strdup(log_filename_base), time_val);
    return log_filename;
}

flush_log(uv_check_t *handle) {
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
            rotate_log();
            delete_older_logs(handle->loop);
        }
    }

}

bool log_init(uv_loop_t *ziti_loop, bool is_multi_writer) {

    uv_timeval64_t file_time;
    uv_gettimeofday(&file_time);
    start_time = calloc(1, sizeof(struct tm));
    struct tm* now_tm = gmtime(&file_time.tv_sec);
    memcpy(start_time, now_tm, sizeof(struct tm));

    delete_older_logs(ziti_loop);
    multi_writer = is_multi_writer;

    log_flusher = calloc(1, sizeof(uv_check_t));
    uv_check_init(ziti_loop, log_flusher);
    log_flusher->data = start_time;
    uv_unref((uv_handle_t *) log_flusher);
    uv_check_start(log_flusher, flush_log);


    log_filename = get_log_filename(start_time);

    if (!open_log(log_filename)) {
        return false;
    }
#if _WIN32
    SvcReportEvent(TEXT(log_filename), EVENTLOG_INFORMATION_TYPE);
#endif
    return true;
}

struct tm* get_log_start_time() {
    return start_time;
}

char* get_log_file_name(){
    return log_filename;
}

static char* parse_level(int level) {
    const char* err_level = malloc(7 * sizeof(char));
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
        fputc('\n', ziti_tunneler_log);
        fprintf(ziti_tunneler_log, "[%s] %7s %s ", curr_time, parse_level(level), loc);
        fwrite(msg, 1, msglen, ziti_tunneler_log);
    }

    if(multi_writer) {
        printf("\n[%s] %7s %s %.*s", curr_time, parse_level(level), loc, msglen, msg);
    }

}

bool open_log(char* log_filename) {
    if((ziti_tunneler_log=fopen(log_filename,"a")) == NULL) {
        printf("Could not open logs file %s", log_filename);
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
    uv_check_stop(log_flusher);
}

void rotate_log() {
    close_log();

    uv_timeval64_t file_time;
    uv_gettimeofday(&file_time);
    struct tm* orig_time = gmtime(&file_time.tv_sec);
    memcpy(start_time, orig_time, sizeof(struct tm));
    log_filename = get_log_filename();

    open_log(log_filename);
}

void delete_older_logs(uv_loop_t *ziti_loop) {
    char curr_path[FILENAME_MAX]; //create string buffer to hold path
    GetCurrentDir( curr_path, FILENAME_MAX );

    char log_path[FILENAME_MAX];
    sprintf(log_path, "%s/logs", curr_path);

    uv_fs_t fs;
    int rc = uv_fs_scandir(ziti_loop, &fs, log_path, 0, NULL);
    if (rc < 7) {
        if (rc < 0) {
            ZITI_LOG(ERROR, "failed to scan dir[%s]: %d/%s", log_path, rc, uv_strerror(rc));
        } else {
            ZITI_LOG(TRACE, "Log files count in [%s] is %d, not deleting log files.", log_path, rc);
            uv_fs_req_cleanup(&fs);
        }
        return;
    }

    char **log_files = calloc(rc + 1 , sizeof(char *));
    uv_dirent_t file;
    int rotation_cnt = 0;
    while (uv_fs_scandir_next(&fs, &file) == 0) {
        ZITI_LOG(TRACE, "log file = %s %d", file.name, file.type);

        if (file.type == UV_DIRENT_FILE) {
            if (memcmp(file.name, log_filename_base, sizeof(log_filename_base)) == 0) {
                log_files[rotation_cnt] = strdup(file.name);
                rotation_cnt++;
            }
        }
    }

    char currpath[FILENAME_MAX]; //create string buffer to hold path
    GetCurrentDir( currpath, FILENAME_MAX );

    char logpath[FILENAME_MAX];
    sprintf(logpath, "%s/logs", currpath);
    int rotation_index = rotation_cnt;
    while (rotation_index > rotation_count) {
        char *old_log= calloc(FILENAME_MAX, sizeof(char));
        int old_idx = -1;

        for(int idx =0; idx < rotation_cnt; idx++) {
            if (*old_log == NULL && log_files[idx]) {
                old_log = log_files[idx];
                old_idx = idx;
                continue;
            }
            if (*old_log == NULL) {
                continue;
            }
            if (strcmp(old_log, log_files[idx]) > 0 ) {
                old_log = log_files[idx];
                old_idx = idx;
            }
        }
        if (*old_log != NULL) {
            char* logfile_to_delete = calloc(MAXPATHLEN, sizeof(char*));
            sprintf(logfile_to_delete, "%s/%s", logpath, old_log);
            ZITI_LOG(INFO, "Deleting old log file %s", logfile_to_delete);
            remove(logfile_to_delete);
            free(logfile_to_delete);
            rotation_index--;
        }
        free (old_log);
        log_files[old_idx] = NULL;
    }

    // clean up resources
    uv_fs_req_cleanup(&fs);
    for(int idx =0; idx < rotation_cnt; idx++){
        // older files are already deleted and free'd
        if (log_files[idx]) {
            free(log_files[idx]);
        }
    }
    free(log_files);
}
