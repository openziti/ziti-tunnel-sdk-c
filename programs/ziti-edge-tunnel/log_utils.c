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

static FILE *ziti_tunneler_log = NULL;
static uv_check_t *log_flusher;
static struct tm *start_time;
char* log_filename;
static bool multi_writer = false;

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
    sprintf(log_filename, "%s/ziti-tunneler.log.%s", log_path, time_val);
    return log_filename;
}

flush_log() {
    if (ziti_tunneler_log != NULL) {
        fflush(ziti_tunneler_log);
    }
    if (multi_writer) {
        fflush(stdout);
    }
}

bool log_init(uv_loop_t *ziti_loop, bool is_multi_writer) {
    multi_writer = is_multi_writer;

    log_flusher = calloc(1, sizeof(uv_check_t));
    uv_check_init(ziti_loop, log_flusher);
    uv_check_start(log_flusher, flush_log);

    uv_timeval64_t file_time;
    uv_gettimeofday(&file_time);
    start_time = gmtime(&file_time.tv_sec);

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

    if (start_time->tm_mday < tm->tm_mday) {
        rotate_log();
    }

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
    }
}

void stop_log_check() {
    uv_check_stop(log_flusher);
}

void rotate_log() {
    close_log();

    uv_timeval64_t file_time;
    uv_gettimeofday(&file_time);
    start_time = gmtime(&file_time.tv_sec);
    char* log_filename = get_log_filename();

    open_log(log_filename);
}
