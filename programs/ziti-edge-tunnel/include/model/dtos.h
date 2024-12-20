/*
 Copyright NetFoundry Inc.

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
XX(ZtAPI, model_string, none, ztAPI, __VA_ARGS__) \
XX(ConfigTypes, model_string, array, ConfigTypes, __VA_ARGS__)

#define TUNNEL_METRICS(XX, ...) \
XX(Up, model_number, none, Up, __VA_ARGS__) \
XX(Down, model_number, none, Down, __VA_ARGS__)

#define TUNNEL_IDENTITY(XX, ...) \
XX(Name, model_string, none, Name, __VA_ARGS__) \
XX(Identifier, model_string, none, Identifier, __VA_ARGS__) \
XX(FingerPrint, model_string, none, FingerPrint, __VA_ARGS__) \
XX(Active, model_bool, none, Active, __VA_ARGS__) \
XX(Loaded, model_bool, none, Loaded, __VA_ARGS__) \
XX(Config, tunnel_config, ptr, Config, __VA_ARGS__) \
XX(ControllerVersion, model_string, none, ControllerVersion, __VA_ARGS__) \
XX(IdFileStatus, model_bool, none, IdFileStatus, __VA_ARGS__) \
XX(NeedsExtAuth, model_bool, none, NeedsExtAuth, __VA_ARGS__) \
XX(ExtAuthProviders, model_string, list, ExtAuthProviders, __VA_ARGS__) \
XX(MfaEnabled, model_bool, none, MfaEnabled, __VA_ARGS__) \
XX(MfaNeeded, model_bool, none, MfaNeeded, __VA_ARGS__) \
XX(Services, tunnel_service, array, Services, __VA_ARGS__) \
XX(Metrics, tunnel_metrics, none, Metrics, __VA_ARGS__) \
XX(Tags, model_string, array, Tags, __VA_ARGS__) \
XX(MfaMinTimeout, model_number, none, MfaMinTimeout, __VA_ARGS__) \
XX(MfaMaxTimeout, model_number, none, MfaMaxTimeout, __VA_ARGS__) \
XX(MfaMinTimeoutRem, model_number, none, MfaMinTimeoutRem, __VA_ARGS__) \
XX(MfaMaxTimeoutRem, model_number, none, MfaMaxTimeoutRem, __VA_ARGS__) \
XX(MinTimeoutRemInSvcEvent, model_number, none, MinTimeoutRemInSvcEvent, __VA_ARGS__) \
XX(MaxTimeoutRemInSvcEvent, model_number, none, MaxTimeoutRemInSvcEvent, __VA_ARGS__) \
XX(MfaLastUpdatedTime, timestamp, ptr, MfaLastUpdatedTime, __VA_ARGS__) \
XX(ServiceUpdatedTime, timestamp, ptr, ServiceUpdatedTime, __VA_ARGS__) \
XX(Deleted, model_bool, none, Deleted, __VA_ARGS__) \
XX(Notified, model_bool, none, Notified, __VA_ARGS__)

#define TUNNEL_ADDRESS(XX, ...) \
XX(IsHost, model_bool, none, IsHost, __VA_ARGS__) \
XX(HostName, model_string, none, HostName, __VA_ARGS__) \
XX(IP, model_string, none, IP, __VA_ARGS__) \
XX(Prefix, model_number, none, Prefix, __VA_ARGS__)

#define TUNNEL_PORT_RANGE(XX, ...) \
XX(High, model_number, none, High, __VA_ARGS__) \
XX(Low, model_number, none, Low, __VA_ARGS__)

#define TUNNEL_POSTURE_CHECK(XX, ...) \
XX(IsPassing, model_bool, none, IsPassing, __VA_ARGS__) \
XX(QueryType, model_string, none, QueryType, __VA_ARGS__) \
XX(Id, model_string, none, Id, __VA_ARGS__) \
XX(Timeout, model_number, none, Timeout, __VA_ARGS__)  \
XX(TimeoutRemaining, model_number, none, TimeoutRemaining, __VA_ARGS__)

#define TUNNEL_SERVICE_PERMISSIONS(XX,...) \
XX(Bind, model_bool, none, Bind, __VA_ARGS__) \
XX(Dial, model_bool, none, Dial, __VA_ARGS__)

#define TUNNEL_SERVICE(XX, ...) \
XX(Id, model_string, none, Id, __VA_ARGS__) \
XX(Name, model_string, none, Name, __VA_ARGS__) \
XX(Protocols, model_string, array, Protocols, __VA_ARGS__) \
XX(Addresses, tunnel_address, array, Addresses, __VA_ARGS__) \
XX(AllowedSourceAddresses, tunnel_address, array, AllowedSourceAddresses, __VA_ARGS__) \
XX(Ports, tunnel_port_range, array, Ports, __VA_ARGS__)  \
XX(OwnsIntercept, model_bool, none, OwnsIntercept, __VA_ARGS__) \
XX(PostureChecks, tunnel_posture_check, array, PostureChecks, __VA_ARGS__) \
XX(IsAccessible, model_bool, none, IsAccessible, __VA_ARGS__) \
XX(Timeout, model_number, none, Timeout, __VA_ARGS__)         \
XX(TimeoutRemaining, model_number, none, TimeoutRemaining, __VA_ARGS__) \
XX(Permissions, tunnel_service_permissions , none, Permissions, __VA_ARGS__)

#define TUNNEL_STATUS(XX, ...) \
XX(Active, model_bool, none, Active, __VA_ARGS__) \
XX(Duration, model_number, none, Duration, __VA_ARGS__) \
XX(StartTime, timestamp, none, StartTime, __VA_ARGS__) \
XX(Identities, tunnel_identity, array, Identities, __VA_ARGS__) \
XX(IpInfo, ip_info, ptr, IpInfo, __VA_ARGS__) \
XX(LogLevel, model_string, none, LogLevel, __VA_ARGS__) \
XX(ServiceVersion, service_version, ptr, ServiceVersion, __VA_ARGS__) \
XX(TunIpv4, model_string, none, TunIpv4, __VA_ARGS__) \
XX(TunPrefixLength, model_number, none, TunIpv4Mask, __VA_ARGS__) \
XX(AddDns, model_bool, none, AddDns, __VA_ARGS__) \
XX(ApiPageSize, model_number, none, ApiPageSize, __VA_ARGS__) \
XX(TunName, model_string, none, TunName, __VA_ARGS__)\
XX(ConfigDir, model_string, none, ConfigDir, __VA_ARGS__)

#define IP_INFO(XX, ...) \
XX(Ip, model_string, none, Ip, __VA_ARGS__) \
XX(Subnet, model_string, none, Subnet, __VA_ARGS__) \
XX(MTU, model_number, none, MTU, __VA_ARGS__) \
XX(DNS, model_string, none, DNS, __VA_ARGS__)

#define SERVICE_VERSION(XX, ...) \
XX(Version, model_string, none, Version, __VA_ARGS__) \
XX(Revision, model_string, none, Revision, __VA_ARGS__) \
XX(BuildDate, model_string, none, BuildDate, __VA_ARGS__)

DECLARE_MODEL(tunnel_config, TUNNEL_CONFIG)
DECLARE_MODEL(tunnel_metrics, TUNNEL_METRICS)
DECLARE_MODEL(tunnel_address, TUNNEL_ADDRESS)
DECLARE_MODEL(tunnel_port_range, TUNNEL_PORT_RANGE)
DECLARE_MODEL(tunnel_posture_check, TUNNEL_POSTURE_CHECK)
DECLARE_MODEL(tunnel_service_permissions, TUNNEL_SERVICE_PERMISSIONS)
DECLARE_MODEL(tunnel_service, TUNNEL_SERVICE)
DECLARE_MODEL(tunnel_identity, TUNNEL_IDENTITY)
DECLARE_MODEL(ip_info, IP_INFO)
DECLARE_MODEL(service_version, SERVICE_VERSION)
DECLARE_MODEL(tunnel_status, TUNNEL_STATUS)

#ifdef __cplusplus
}
#endif

#endif //ZITI_TUNNEL_SDK_C_DTOS_H
