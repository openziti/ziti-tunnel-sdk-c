#ifndef ZITI_TUNNEL_SDK_C_WINDOWS_SERVICE_H
#define ZITI_TUNNEL_SDK_C_WINDOWS_SERVICE_H

#if _WIN32
#include <stdbool.h>
#include <winsock2.h>
#include <windows.h>

#ifndef PATH_MAX //normalize to PATH_MAX even on vs 2022 and arm
#ifdef MAX_PATH
#define PATH_MAX MAX_PATH
#else
#error "PATH_MAX and MAX_PATH are not defined, PATH_MAX cannot be set"
#endif
#endif

#define SVCNAME TEXT("ziti")
#define DISPLAYSVCNAME TEXT("Ziti Desktop Edge Service")
#define SVCDESCRIPTION TEXT("Access your Networks Secured by Ziti")
#define APPNAME TEXT("Ziti Desktop Edge for Windows")

#ifdef __cplusplus
extern "C" {
#endif

VOID SvcStart(VOID);
VOID SvcInstall(void);
VOID WINAPI SvcMain( DWORD, LPTSTR * );
VOID ReportSvcStatus( DWORD, DWORD, DWORD );
VOID SvcInit( DWORD, LPTSTR * );
VOID SvcReportEvent( LPTSTR, DWORD );
VOID SvcDelete(void);
DWORD WINAPI ServiceWorkerThread (LPVOID lpParam);
DWORD WINAPI LphandlerFunctionEx(
        DWORD dwControl,
        DWORD dwEventType,
        LPVOID lpEventData,
        LPVOID lpContext
);

void scm_service_init(char *config_dir);
void scm_service_run(const char *);
void scm_running_event();
void scm_service_stop();
bool stop_windows_service();

DWORD get_process_path(LPTSTR, DWORD);

bool scm_grant_se_debug();

#ifdef __cplusplus
}
#endif

#endif // _WIN32

#endif //ZITI_TUNNEL_SDK_C_WINDOWS_SERVICE_H
