/*
Copyright 2019-2020 NetFoundry, Inc.

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

#include <windows/windows-service.h>
#include <stdio.h>
#include <config-utils.h>
#include <windows/windows-events.h>

#include <winuser.h>
#include <powrprof.h>
#include <windows/powrprofex.h>
#include <wtsapi32.h>
#include <winsock2.h>
#include <windows.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "Powrprof.lib")
#pragma comment(lib, "Wtsapi32.lib")

SERVICE_STATUS          gSvcStatus;
SERVICE_STATUS_HANDLE   gSvcStatusHandle;
HANDLE                  ghSvcStopEvent = NULL;
HPOWERNOTIFY hPowernotify;
// LPHANDLER_FUNCTION_EX LphandlerFunctionEx;
// DEV_BROADCAST_DEVICEINTERFACE NotificationFilter;
// HDEVNOTIFY hDeviceNotify;

//LPCTSTR SVCNAME = "ziti-edge-tunnel";
//
// Purpose:
//   Entry point for the process
//
// Parameters:
//   None
//
// Return value:
//   None, defaults to 0 (zero)
//
int SvcStart(TCHAR *opt)
{
    // the service is probably being started by the SCM.
    // Add any additional services for the process to this table.
    SERVICE_TABLE_ENTRY DispatchTable[] =
            {
                    { SVCNAME, (LPSERVICE_MAIN_FUNCTION) SvcMain },
                    { NULL, NULL }
            };

    // This call returns when the service has stopped.
    // The process should simply terminate when the call returns.

    if (!StartServiceCtrlDispatcher( DispatchTable ))
    {
        return 0;
    }
}

//
// Purpose:
//   Installs a service in the SCM database
//
// Parameters:
//   None
//
// Return value:
//   None
//
VOID SvcInstall()
{
    SC_HANDLE schSCManager;
    SC_HANDLE schService;
    TCHAR szPath[MAX_PATH];

    if( !GetModuleFileName( NULL, szPath, MAX_PATH ) )
    {
        printf("Cannot install service (%d)\n", GetLastError());
        return;
    }

    // Get a handle to the SCM database.

    schSCManager = OpenSCManager(
            NULL,                    // local computer
            NULL,                    // ServicesActive database
            SC_MANAGER_ALL_ACCESS);  // full access rights

    if (NULL == schSCManager)
    {
        printf("OpenSCManager failed (%d)\n", GetLastError());
        return;
    }

    // Create the service

    schService = CreateService(
            schSCManager,              // SCM database
            SVCNAME,                   // name of service
            DISPLAYSVCNAME,            // service name to display
            SERVICE_ALL_ACCESS,        // desired access
            SERVICE_WIN32_OWN_PROCESS, // service type
            SERVICE_DEMAND_START,      // start type
            SERVICE_ERROR_NORMAL,      // error control type
            szPath,                    // path to service's binary
            NULL,                      // no load ordering group
            NULL,                      // no tag identifier
            NULL,                      // no dependencies
            NULL,                      // LocalSystem account
            NULL);                     // no password

    if (schService == NULL)
    {
        printf("CreateService failed (%d)\n", GetLastError());
        CloseServiceHandle(schSCManager);
        return;
    }
    else printf("Service installed successfully\n");

    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
}

//
// Purpose:
//   Entry point for the service
//
// Parameters:
//   dwArgc - Number of arguments in the lpszArgv array
//   lpszArgv - Array of strings. The first string is the name of
//     the service and subsequent strings are passed by the process
//     that called the StartService function to start the service.
//
// Return value:
//   None.
//
VOID WINAPI SvcMain( DWORD dwArgc, LPTSTR *lpszArgv )
{
    // Register the handler function for the service

    /*gSvcStatusHandle = RegisterServiceCtrlHandler(
            SVCNAME,
            SvcCtrlHandler);*/
    gSvcStatusHandle = RegisterServiceCtrlHandlerEx(
            SVCNAME,
            LphandlerFunctionEx, NULL);

    if( !gSvcStatusHandle )
    {
        SvcReportEvent(TEXT("RegisterServiceCtrlHandler failed"), EVENTLOG_ERROR_TYPE);
        return;
    }

    // These SERVICE_STATUS members remain as set here

    gSvcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    gSvcStatus.dwServiceSpecificExitCode = 0;

    // Report initial status to the SCM

    ReportSvcStatus( SERVICE_START_PENDING, NO_ERROR, 3000 );

    // Perform service-specific initialization and work.
    char* config_dir = get_system_config_path();
    scm_service_init(config_dir);

    SvcInit( dwArgc, lpszArgv );
}

//
// Purpose:
//   The service code
//
// Parameters:
//   dwArgc - Number of arguments in the lpszArgv array
//   lpszArgv - Array of strings. The first string is the name of
//     the service and subsequent strings are passed by the process
//     that called the StartService function to start the service.
//
// Return value:
//   None
//
VOID SvcInit( DWORD dwArgc, LPTSTR *lpszArgv)
{
    // Declare and set any required variables.
    //   Be sure to periodically call ReportSvcStatus() with
    //   SERVICE_START_PENDING. If initialization fails, call
    //   ReportSvcStatus with SERVICE_STOPPED.

    // Create an event. The control handler function, SvcCtrlHandler,
    // signals this event when it receives the stop control code.

    ghSvcStopEvent = CreateEvent(
            NULL,    // default security attributes
            TRUE,    // manual reset event
            FALSE,   // not signaled
            NULL);   // no name

    if ( ghSvcStopEvent == NULL)
    {
        ReportSvcStatus( SERVICE_STOPPED, GetLastError(), 0 );
        return;
    }

    // register for power events
    DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS parameters = { DeviceNotifyCallbackRoutine, NULL };

    /*PowerRegisterSuspendResumeNotification(DEVICE_NOTIFY_CALLBACK, &parameters, &notify);*/

    hPowernotify = RegisterSuspendResumeNotification(
            &parameters,
            DEVICE_NOTIFY_CALLBACK
    );
    if (NULL == hPowernotify) {
        SvcReportEvent(TEXT("Ziti Edge Tunnel could not register power events"), EVENTLOG_INFORMATION_TYPE);
    } else {
        SvcReportEvent(TEXT("Ziti Edge Tunnel registered for power events"), EVENTLOG_INFORMATION_TYPE);
    }

    HWND current_process = GetCurrentProcess();
    WINBOOL sessionRegistered = WTSRegisterSessionNotification(current_process, NOTIFY_FOR_THIS_SESSION);
    if (sessionRegistered) {
        SvcReportEvent(TEXT("Ziti Edge Tunnel registered for session events"), EVENTLOG_INFORMATION_TYPE);
    } else {
        SvcReportEvent(TEXT("Ziti Edge Tunnel could not register for session events"), EVENTLOG_INFORMATION_TYPE);
    }

    // Report running status when initialization is complete.

    ReportSvcStatus( SERVICE_RUNNING, NO_ERROR, 0 );

    // start tunnel
    CreateThread (NULL, 0, ServiceWorkerThread, lpszArgv, 0, NULL);

    SvcReportEvent(TEXT("Ziti Edge Tunnel Run"), EVENTLOG_INFORMATION_TYPE);

    while(1)
    {
        // Check whether to stop the service.

        WaitForSingleObject(ghSvcStopEvent, INFINITE);

        SvcReportEvent(TEXT("Ziti Edge Tunnel Stopped"), EVENTLOG_INFORMATION_TYPE);
        ReportSvcStatus( SERVICE_STOPPED, NO_ERROR, 0 );
        // PowerUnregisterSuspendResumeNotification(notify);
        return;
    }
}

DWORD WINAPI ServiceWorkerThread (LPVOID lpParam)
{
    //  Periodically check if the service has been requested to stop
    scm_service_run(lpParam);
    // when service stops and returns, stop the service in scm
    stop_windows_service();
    return ERROR_SUCCESS;
}

//
// Purpose:
//   Sets the current service status and reports it to the SCM.
//
// Parameters:
//   dwCurrentState - The current state (see SERVICE_STATUS)
//   dwWin32ExitCode - The system error code
//   dwWaitHint - Estimated time for pending operation,
//     in milliseconds
//
// Return value:
//   None
//
VOID ReportSvcStatus( DWORD dwCurrentState,
                      DWORD dwWin32ExitCode,
                      DWORD dwWaitHint)
{
    static DWORD dwCheckPoint = 1;

    // Fill in the SERVICE_STATUS structure.

    gSvcStatus.dwCurrentState = dwCurrentState;
    gSvcStatus.dwWin32ExitCode = dwWin32ExitCode;
    gSvcStatus.dwWaitHint = dwWaitHint;

    if (dwCurrentState == SERVICE_START_PENDING)
        gSvcStatus.dwControlsAccepted = 0;
    else gSvcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;

    if ( (dwCurrentState == SERVICE_RUNNING) ||
         (dwCurrentState == SERVICE_STOPPED) )
        gSvcStatus.dwCheckPoint = 0;
    else gSvcStatus.dwCheckPoint = dwCheckPoint++;

    // Report the status of the service to the SCM.
    SetServiceStatus( gSvcStatusHandle, &gSvcStatus );
}

//
// Purpose:
//   Called by SCM whenever a control code is sent to the service
//   using the ControlService function.
//
// Parameters:
//   dwCtrl - control code
//
// Return value:
//   None
//
VOID WINAPI SvcCtrlHandler( DWORD dwCtrl )
{
    // Handle the requested control code.

    switch(dwCtrl)
    {
        case SERVICE_CONTROL_STOP:
            ReportSvcStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);

            // stops the running tunnel service
            scm_service_stop();
            // stops the windows service in scm
            stop_windows_service();

            return;

        case SERVICE_CONTROL_INTERROGATE:
            break;

        default:
            break;
    }

}

//
// Purpose:
//   Logs messages to the event log
//
// Parameters:
//   szFunction - name of function that failed
//
// Return value:
//   None
//
// Remarks:
//   The service must have an entry in the Application event log.
//
VOID SvcReportEvent(LPTSTR szMessage, DWORD eventType)
{
    HANDLE hEventSource;
    LPCTSTR lpszStrings[2];
    TCHAR Buffer[80];

    hEventSource = RegisterEventSource(NULL, SVCNAME);

    if( NULL != hEventSource )
    {
        snprintf(Buffer, 80, TEXT("%s, reported status : %d"), szMessage, GetLastError());

        lpszStrings[0] = SVCNAME;
        lpszStrings[1] = Buffer;

        ReportEvent(hEventSource,        // event log handle
                    eventType,           // event type
                    0,                   // event category
                    0,                   // event identifier
                    NULL,                // no security identifier
                    2,                   // size of lpszStrings array
                    0,                   // no binary data
                    lpszStrings,         // array of strings
                    NULL);               // no binary data

        DeregisterEventSource(hEventSource);
    }
}

//
// Purpose:
//   Deletes a service from the SCM database
//
// Parameters:
//   None
//
// Return value:
//   None
//
VOID SvcDelete()
{
    SC_HANDLE schSCManager;
    SC_HANDLE schService;
    SERVICE_STATUS ssStatus;

    // Get a handle to the SCM database.

    schSCManager = OpenSCManager(
            NULL,                    // local computer
            NULL,                    // ServicesActive database
            SC_MANAGER_ALL_ACCESS);  // full access rights

    if (NULL == schSCManager)
    {
        printf("OpenSCManager failed (%d)\n", GetLastError());
        return;
    }

    // Get a handle to the service.

    schService = OpenService(
            schSCManager,       // SCM database
            SVCNAME,            // name of service
            DELETE);            // need delete access

    if (schService == NULL)
    {
        printf("OpenService failed (%d)\n", GetLastError());
        CloseServiceHandle(schSCManager);
        return;
    }

    // Delete the service.

    if (! DeleteService(schService) )
    {
        printf("DeleteService failed (%d)\n", GetLastError());
    }
    else printf("Service deleted successfully\n");

    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
}

//
// Purpose:
//   Stops a service from the application
//
// Parameters:
//   None
//
// Return value:
//   None
//
void stop_windows_service() {
    SetEvent(ghSvcStopEvent);
    ReportSvcStatus(gSvcStatus.dwCurrentState, NO_ERROR, 0);
}

DWORD get_process_path(LPTSTR lpBuffer, DWORD  nBufferLength) {
    return GetModuleFileName(0, lpBuffer, nBufferLength);
}

DWORD LphandlerFunctionEx(
 DWORD dwControl,
 DWORD dwEventType,
 LPVOID lpEventData,
 LPVOID lpContext
) {

    switch (dwControl) {
        case SERVICE_CONTROL_STOP:
            ReportSvcStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);

            // stops the running tunnel service
            scm_service_stop();
            // stops the windows service in scm
            stop_windows_service();

            return 0;

        case SERVICE_CONTROL_POWEREVENT:
            if (dwEventType == PBT_APMRESUMEAUTOMATIC || dwEventType == PBT_APMRESUMESUSPEND) {
                SvcReportEvent(TEXT("Ziti Edge Tunnel received power resume event"), EVENTLOG_INFORMATION_TYPE);
            }
            break;

        case SERVICE_CONTROL_SESSIONCHANGE:
            if (dwEventType == WTS_SESSION_UNLOCK) {
                SvcReportEvent(TEXT("Ziti Edge Tunnel received session unlock event"), EVENTLOG_INFORMATION_TYPE);
            }
            break;
    }
}
