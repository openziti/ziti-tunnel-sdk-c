#ifndef ZITI_TUNNEL_SDK_C_WINDOWS_SERVICE_H
#define ZITI_TUNNEL_SDK_C_WINDOWS_SERVICE_H

#if _WIN32
#include <stdbool.h>
#include <windows.h>

#define SVCNAME TEXT("ziti-edge-tunnel")
#define DISPLAYSVCNAME TEXT("Ziti Desktop Edge Service")
#define SVCDESCRIPTION TEXT("Access your Networks Secured by Ziti")
//
// MessageId: SVC_ERROR
//
// MessageText:
//
// An error has occurred (%2).
//
#define SVC_ERROR ((DWORD)0xC0020001L)

int SvcStart(TCHAR *);
VOID SvcInstall(void);
VOID WINAPI SvcCtrlHandler( DWORD );
VOID WINAPI SvcMain( DWORD, LPTSTR * );
VOID ReportSvcStatus( DWORD, DWORD, DWORD );
VOID SvcInit( DWORD, LPTSTR * );
VOID SvcReportEvent( LPTSTR );
VOID SvcDelete(void);
DWORD WINAPI ServiceWorkerThread (LPVOID lpParam);


#ifdef __cplusplus
extern "C" {
#endif

bool log_init();
void windows_log_writer(int , const char *, const char *, size_t);
void scm_service_init(char *config_dir);
void scm_service_run(void *);
char* get_system_config_path();
void scm_service_stop();
void stop_windows_service();

#ifdef __cplusplus
}
#endif

#endif

#endif //ZITI_TUNNEL_SDK_C_WINDOWS_SERVICE_H
