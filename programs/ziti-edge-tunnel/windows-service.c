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

#include <winuser.h>
#include <service-utils.h>
#include <windows.h>

#pragma comment(lib, "advapi32.lib")

SERVICE_STATUS          gSvcStatus;
SERVICE_STATUS_HANDLE   gSvcStatusHandle;
HANDLE                  ghSvcStopEvent = NULL;
HANDLE                  ghSvcRunningEvent = NULL;

//LPCTSTR SVCNAME = "ziti";
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
VOID SvcStart(VOID)
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
        printf("StartServiceCtrlDispatcher failed (%ld)\n", GetLastError());
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
        printf("Cannot install service (%ld)\n", GetLastError());
        return;
    }

    // Get a handle to the SCM database.

    schSCManager = OpenSCManager(
            NULL,                    // local computer
            NULL,                    // ServicesActive database
            SC_MANAGER_ALL_ACCESS);  // full access rights

    if (NULL == schSCManager)
    {
        printf("OpenSCManager failed (%ld)\n", GetLastError());
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
        printf("CreateService failed (%ld)\n", GetLastError());
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

    // start tunnel
    CreateThread (NULL, 0, ServiceWorkerThread, lpszArgv[0], 0, NULL);

    // Check whether the service is started

    // Create an event. The control handler function, SvcCtrlHandler,
    // signals this event when it receives the running control code.

    ghSvcRunningEvent = CreateEvent(
            NULL,    // default security attributes
            TRUE,    // manual reset event
            FALSE,   // not signaled
            NULL);   // no name

    if ( ghSvcRunningEvent == NULL)
    {
        ReportSvcStatus( SERVICE_STOPPED, GetLastError(), 0 );
        return;
    }

    // Report running status when initialization is complete.

    // If the service receive a running event with in 150 seconds, set the service to running state
    // otherwise stop the service

    if (WaitForSingleObject(ghSvcRunningEvent, 150000) == WAIT_OBJECT_0) {
        ReportSvcStatus( SERVICE_RUNNING, NO_ERROR, 0 );
        SvcReportEvent(TEXT("Ziti Edge Tunnel Run"), EVENTLOG_INFORMATION_TYPE);
    } else {
        SvcReportEvent(TEXT("Ziti Edge Tunnel Stopped"), EVENTLOG_INFORMATION_TYPE);
        ReportSvcStatus( SERVICE_STOPPED, NO_ERROR, 0 );
        return;
    }

    // Check whether to stop the service.

    WaitForSingleObject(ghSvcStopEvent, INFINITE);

    ReportSvcStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);

    scm_service_stop();

    SvcReportEvent(TEXT("Ziti Edge Tunnel Stopped"), EVENTLOG_INFORMATION_TYPE);
    ReportSvcStatus( SERVICE_STOPPED, NO_ERROR, 0 );
}

DWORD WINAPI ServiceWorkerThread (LPVOID lpParam)
{
    //  Periodically check if the service has been requested to stop
    scm_service_run(APPNAME);
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
    else {
        gSvcStatus.dwControlsAccepted = SERVICE_ACCEPT_SESSIONCHANGE | SERVICE_ACCEPT_POWEREVENT | SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    }

    if ( (dwCurrentState == SERVICE_RUNNING) ||
         (dwCurrentState == SERVICE_STOPPED) )
        gSvcStatus.dwCheckPoint = 0;
    else gSvcStatus.dwCheckPoint = dwCheckPoint++;

    // Report the status of the service to the SCM.
    SetServiceStatus( gSvcStatusHandle, &gSvcStatus );
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
        snprintf(Buffer, 80, TEXT("%s, reported status : %ld"), szMessage, GetLastError());

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

    // Get a handle to the SCM database.

    schSCManager = OpenSCManager(
            NULL,                    // local computer
            NULL,                    // ServicesActive database
            SC_MANAGER_ALL_ACCESS);  // full access rights

    if (NULL == schSCManager)
    {
        printf("OpenSCManager failed (%ld)\n", GetLastError());
        return;
    }

    // Get a handle to the service.

    schService = OpenService(
            schSCManager,       // SCM database
            SVCNAME,            // name of service
            DELETE);            // need delete access

    if (schService == NULL)
    {
        printf("OpenService failed (%ld)\n", GetLastError());
        CloseServiceHandle(schSCManager);
        return;
    }

    // Delete the service.

    if (! DeleteService(schService) )
    {
        printf("DeleteService failed (%ld)\n", GetLastError());
    }
    else printf("Service deleted successfully\n");

    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
}


//
// Purpose:
//   Sets the service to running state from the application
//
// Parameters:
//   None
//
// Return value:
//   None
//
void scm_running_event() {
    SetEvent(ghSvcRunningEvent);
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
bool stop_windows_service() {
    return SetEvent(ghSvcStopEvent);
}

DWORD get_process_path(LPTSTR lpBuffer, DWORD  nBufferLength) {
    return GetModuleFileName(0, lpBuffer, nBufferLength);
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
DWORD LphandlerFunctionEx(
 DWORD dwControl,
 DWORD dwEventType,
 LPVOID lpEventData,
 LPVOID lpContext
) {

    switch (dwControl) {
        case SERVICE_CONTROL_STOP:
            ReportSvcStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);

            // send a stop event
            stop_windows_service(true);

            return 0;

        case SERVICE_CONTROL_POWEREVENT:
            if (dwEventType == PBT_APMRESUMEAUTOMATIC || dwEventType == PBT_APMRESUMESUSPEND) {
                endpoint_status_change(true, false);
            }
            break;

        case SERVICE_CONTROL_SESSIONCHANGE:
            if (dwEventType == WTS_SESSION_UNLOCK) {
                endpoint_status_change(false, true);
            }
            break;

        default:
            //printf("unhandled control code from SCM (%ld)\n", dwControl);
            break;
    }

    return 0;
}
