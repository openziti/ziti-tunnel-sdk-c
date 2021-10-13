#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <direct.h>
#include <stdbool.h>
#include <ziti/ziti_log.h>
#include <time.h>
#include "windows/windows-service.h"

#define GetCurrentDir _getcwd

static FILE *ziti_tunneler_log = NULL;

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

    char* log_filename = malloc(FILENAME_MAX * sizeof(char));
    sprintf(log_filename, "%s/ziti-tunneler.log", log_path);
    return log_filename;
}

bool log_init() {
    char* log_filename = get_log_filename();
    SvcReportEvent(TEXT( log_filename), EVENTLOG_INFORMATION_TYPE);
    if((ziti_tunneler_log=freopen(log_filename,"a", stdout)) == NULL) {
        printf("Could not open logs file %s", log_filename);
        return false;
    }
    dup2(fileno(stdout), fileno(stderr));

    printf("\n============================================================================");
    printf("\nLogger initialization");
    printf("\n	- log file location: %s", log_filename);
    printf("\n============================================================================");
    return true;
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

void windows_log_writer(int level, const char *loc, const char *msg, size_t msglen) {
    char curr_time[32];
    uv_timeval64_t now;
    uv_gettimeofday(&now);
    struct tm *tm = gmtime(&now.tv_sec);

    snprintf(curr_time, sizeof(curr_time), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
             1900 + tm->tm_year, tm->tm_mon + 1, tm->tm_mday,
             tm->tm_hour, tm->tm_min, tm->tm_sec, now.tv_usec / 1000
    );

    fputc('\n', ziti_tunneler_log);
    fprintf(ziti_tunneler_log, "[%s] %7s %s ", curr_time, parse_level(level), loc);
    fwrite(msg, 1, msglen, ziti_tunneler_log);

}