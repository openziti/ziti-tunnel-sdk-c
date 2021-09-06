/*
Copyright 2019 Netfoundry, Inc.

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

#ifndef ZITI_TUNNEL_SDK_C_DTOS_H
#define ZITI_TUNNEL_SDK_C_DTOS_H

#include "ziti/ziti.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TUNNEL_CONFIG(XX, ...) \
XX(ZtAPI, string, none, ZtAPI, __VA_ARGS__) \
XX(ConfigTypes, string, array, ConfigTypes, __VA_ARGS__)

#define TUNNEL_METRICS(XX, ...) \
XX(Up, string, none, Up, __VA_ARGS__) \
XX(Down, string, none, Down, __VA_ARGS__)

#define TUNNEL_IDENTITY(XX, ...) \
XX(Name, string, none, Name, __VA_ARGS__) \
XX(Identifier, string, none, Identifier, __VA_ARGS__) \
XX(Active, bool, none, Active, __VA_ARGS__) \
XX(Loaded, bool, none, Loaded, __VA_ARGS__) \
XX(Config, tunnel_config, none, Config, __VA_ARGS__) \
XX(ControllerVersion, string, none, ControllerVersion, __VA_ARGS__) \
XX(Status, string, none, Status, __VA_ARGS__) \
XX(MfaEnabled, bool, none, MfaEnabled, __VA_ARGS__) \
XX(MfaNeeded, bool, none, MfaNeeded, __VA_ARGS__) \
XX(Services, tunnel_service, array, Services, __VA_ARGS__) \
XX(Metrics, tunnel_metrics, none, Metrics, __VA_ARGS__) \
XX(Tags, string, array, Tags, __VA_ARGS__) \
XX(MfaMinTimeout, int, none, MfaMinTimeout, __VA_ARGS__) \
XX(MfaMaxTimeout, int, none, MfaMaxTimeout, __VA_ARGS__) \
XX(MfaMinTimeoutRem, int, none, MfaMinTimeoutRem, __VA_ARGS__) \
XX(MfaMaxTimeoutRem, int, none, MfaMaxTimeoutRem, __VA_ARGS__) \
XX(MfaLastUpdatedTime, timestamp, ptr, MfaLastUpdatedTime, __VA_ARGS__) \
XX(ServiceUpdatedTime, timestamp, ptr, ServiceUpdatedTime, __VA_ARGS__) \
XX(Deleted, bool, none, Deleted, __VA_ARGS__)

#define TUNNEL_ADDRESS(XX, ...) \
XX(IsHost, bool, none, IsHost, __VA_ARGS__) \
XX(HostName, string, none, HostName, __VA_ARGS__) \
XX(IP, string, none, IP, __VA_ARGS__) \
XX(Prefix, int, none, Prefix, __VA_ARGS__)

#define TUNNEL_PORT_RANGE(XX, ...) \
XX(High, int, none, High, __VA_ARGS__) \
XX(Low, int, none, Low, __VA_ARGS__)

#define TUNNEL_POSTURE_CHECK(XX, ...) \
XX(IsPassing, bool, none, IsPassing, __VA_ARGS__) \
XX(QueryType, string, none, QueryType, __VA_ARGS__) \
XX(Id, string, none, Id, __VA_ARGS__) \
XX(Timeout, int, none, Timeout, __VA_ARGS__)  \
XX(TimeoutRemaining, int, none, TimeoutRemaining, __VA_ARGS__)

#define TUNNEL_SERVICE(XX, ...) \
XX(Id, string, none, Id, __VA_ARGS__) \
XX(Name, string, none, Name, __VA_ARGS__) \
XX(Protocols, string, array, Protocols, __VA_ARGS__) \
XX(Addresses, tunnel_address, array, Addresses, __VA_ARGS__) \
XX(Ports, tunnel_port_range, array, Ports, __VA_ARGS__)  \
XX(OwnsIntercept, bool, none, OwnsIntercept, __VA_ARGS__) \
XX(PostureChecks, tunnel_posture_check, array, PostureChecks, __VA_ARGS__) \
XX(IsAccessable, bool, none, IsAccessable, __VA_ARGS__) \
XX(Timeout, int, none, Timeout, __VA_ARGS__)         \
XX(TimeoutRemaining, int, none, TimeoutRemaining, __VA_ARGS__)

#define TUNNEL_STATUS(XX, ...) \
XX(Active, bool, none, Active, __VA_ARGS__) \
XX(Duration, int, none, Duration, __VA_ARGS__) \
XX(StartTime, timestamp, none,StartTime, __VA_ARGS__) \
XX(Identities, tunnel_identity, array, Identities, __VA_ARGS__)

DECLARE_MODEL(tunnel_config, TUNNEL_CONFIG)
DECLARE_MODEL(tunnel_metrics, TUNNEL_METRICS)
DECLARE_MODEL(tunnel_address, TUNNEL_ADDRESS)
DECLARE_MODEL(tunnel_port_range, TUNNEL_PORT_RANGE)
DECLARE_MODEL(tunnel_posture_check, TUNNEL_POSTURE_CHECK)
DECLARE_MODEL(tunnel_service, TUNNEL_SERVICE)
DECLARE_MODEL(tunnel_identity, TUNNEL_IDENTITY)
DECLARE_MODEL(tunnel_status, TUNNEL_STATUS)

#ifdef __cplusplus
}
#endif

#endif //ZITI_TUNNEL_SDK_C_DTOS_H
