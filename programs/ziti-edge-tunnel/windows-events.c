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

#include <windows.h>
#include <windows/windows-events.h>
#include <ziti/ziti_log.h>

//  callback function is used for receiving power notifications
// It takes 3 params -
// Context - The context provided when registering for the power notification.
// Type - The type of power event that caused this notification.
// Setting - The value of this parameter depends on the type of notification subscribed to.
ULONG DeviceNotifyCallbackRoutine(
        PVOID Context,
        ULONG Type,
        PVOID Setting
) {

    if (Type == PBT_APMRESUMEAUTOMATIC || Type == PBT_APMRESUMESUSPEND) {
        ZITI_LOG(INFO, "Resume event received");
    }
}

