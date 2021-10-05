/*
 Copyright 2019-2021 NetFoundry Inc.

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

#ifndef ZITI_TUNNEL_SDK_C_EVENTS_H
#define ZITI_TUNNEL_SDK_C_EVENTS_H

#include "ziti/ziti.h"
#include "model/dtos.h"

#ifdef __cplusplus
extern "C" {
#endif

#define STATUS_EVENT(XX, ...) \
XX(Op, string, none, Op, __VA_ARGS__)

#define ACTION_EVENT(XX, ...) \
STATUS_EVENT(XX, __VA_ARGS__) \
XX(Action, string, none, Action, __VA_ARGS__) \
XX(Identifier, string, none, Identifier, __VA_ARGS__)

#define TUNNEL_STATUS_EVENT(XX, ...) \
STATUS_EVENT(XX, __VA_ARGS__) \
XX(Status, tunnel_status, ptr, Status, __VA_ARGS__)

#define IDENTITY_EVENT(XX, ...) \
ACTION_EVENT(XX, __VA_ARGS__) \
XX(Id, tunnel_identity, ptr, Id, __VA_ARGS__)

#define SERVICES_EVENT(XX, ...) \
ACTION_EVENT(XX, __VA_ARGS__) \
XX(AddedServices, tunnel_service, array, AddedServices, __VA_ARGS__) \
XX(RemovedServices, tunnel_service, array, RemovedServices, __VA_ARGS__)

#define MFA_STATUS_EVENT(XX, ...) \
ACTION_EVENT(XX, __VA_ARGS__) \
XX(Successful, bool, none, Successful, __VA_ARGS__) \
XX(Error, string, none, Error, __VA_ARGS__) \
XX(ProvisioningUrl, string, none, ProvisioningUrl, __VA_ARGS__) \
XX(RecoveryCodes, string, array, RecoveryCodes, __VA_ARGS__)

#define TUNNEL_METRICS_EVENT(XX, ...) \
STATUS_EVENT(XX, __VA_ARGS__) \
XX(Identities, tunnel_identity, array, Identities, __VA_ARGS__)

#define TUNNEL_NOTIFICATION_MESSAGE(XX, ...) \
XX(IdentityName, string, none, IdentityName, __VA_ARGS__) \
XX(Identifier, string, none, Identifier, __VA_ARGS__) \
XX(Message, string, none, Message, __VA_ARGS__) \
XX(MfaMinimumTimeout, int, none, MfaMinimumTimeout, __VA_ARGS__) \
XX(MfaMaximumTimeout, int, none, MfaMaximumTimeout, __VA_ARGS__) \
XX(MfaTimeDuration, int, none, MfaTimeDuration, __VA_ARGS__) \
XX(Severity, event_severity, none, Severity, __VA_ARGS__)

#define TUNNEL_NOTIFICATION_EVENT(XX, ...) \
STATUS_EVENT(XX, __VA_ARGS__) \
XX(Notification, notification_message, array, Notification, __VA_ARGS__)

#define EVENT_SEVERITY(XX, ...) \
XX(critical, __VA_ARGS__) \
XX(major, __VA_ARGS__) \
XX(minor, __VA_ARGS__)

#define EVENT_ACTIONS(XX, ...) \
XX(added, __VA_ARGS__) \
XX(removed, __VA_ARGS__) \
XX(updated, __VA_ARGS__) \
XX(bulk, __VA_ARGS__) \
XX(error, __VA_ARGS__) \
XX(changed, __VA_ARGS__) \
XX(normal, __VA_ARGS__) \
XX(connected, __VA_ARGS__) \
XX(disconnected, __VA_ARGS__)

DECLARE_ENUM(event_severity, EVENT_SEVERITY)
DECLARE_ENUM(event, EVENT_ACTIONS)
DECLARE_MODEL(status_event, STATUS_EVENT)
DECLARE_MODEL(action_event, ACTION_EVENT)
DECLARE_MODEL(tunnel_status_event, TUNNEL_STATUS_EVENT)
DECLARE_MODEL(identity_event, IDENTITY_EVENT)
DECLARE_MODEL(services_event, SERVICES_EVENT)
DECLARE_MODEL(mfa_status_event, MFA_STATUS_EVENT)
DECLARE_MODEL(tunnel_metrics_event, TUNNEL_METRICS_EVENT)
DECLARE_MODEL(notification_message, TUNNEL_NOTIFICATION_MESSAGE)
DECLARE_MODEL(notification_event, TUNNEL_NOTIFICATION_EVENT)

#ifdef __cplusplus
}
#endif

#endif //ZITI_TUNNEL_SDK_C_EVENTS_H
