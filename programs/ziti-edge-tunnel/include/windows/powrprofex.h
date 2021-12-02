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

#ifndef ZITI_TUNNEL_SDK_C_POWRPROFEX_H
#define ZITI_TUNNEL_SDK_C_POWRPROFEX_H


// These fragments are taken from the powerprof.h file under the C:\Program Files (x86)\Windows Kits\10\Include\10.0.19041.0\um path
// =========================================
// Power Scheme APIs
// =========================================
//

#define DEVICE_NOTIFY_CALLBACK 2

typedef
ULONG
CALLBACK
DEVICE_NOTIFY_CALLBACK_ROUTINE (
        _In_opt_ PVOID Context,
        _In_ ULONG Type,
        _In_ PVOID Setting
);

typedef DEVICE_NOTIFY_CALLBACK_ROUTINE* PDEVICE_NOTIFY_CALLBACK_ROUTINE;

typedef struct _DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS {
    PDEVICE_NOTIFY_CALLBACK_ROUTINE Callback;
    PVOID Context;
} DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS, *PDEVICE_NOTIFY_SUBSCRIBE_PARAMETERS;

#endif //ZITI_TUNNEL_SDK_C_POWRPROFEX_H
