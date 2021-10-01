#ifndef ZITI_TUNNEL_SDK_C_WINDOWS_SERVICE_H
#define ZITI_TUNNEL_SDK_C_WINDOWS_SERVICE_H

#ifdef __cplusplus
extern "C" {
#endif

#if _WIN32

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

#endif

#ifdef __cplusplus
}
#endif

#endif //ZITI_TUNNEL_SDK_C_WINDOWS_SERVICE_H
