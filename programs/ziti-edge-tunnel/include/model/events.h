//
// Created by marydcouto on 8/20/2021.
//

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
XX(Action, string, none, Action, __VA_ARGS__)

#define TUNNEL_STATUS_EVENT(XX, ...) \
XX(active, bool, none, active, __VA_ARGS__)

#define IDENTITY_EVENT(XX, ...) \
XX(Op, string, none, Op, __VA_ARGS__) \
XX(Action, string, none, Action, __VA_ARGS__) \
XX(Identifier, string, none, Identifier, __VA_ARGS__)   \
XX(Id, tunnel_identity, none, Id, __VA_ARGS__)

#define SERVICES_EVENT(XX, ...) \
XX(Op, string, none, Op, __VA_ARGS__) \
XX(Action, string, none, Action, __VA_ARGS__) \
XX(Identifier, string, none, Identifier, __VA_ARGS__)   \
XX(Id, string, none, Id, __VA_ARGS__)   \
XX(services, tunnel_service, array, services, __VA_ARGS__)

DECLARE_MODEL(status_event, STATUS_EVENT)
DECLARE_MODEL(action_event, ACTION_EVENT)
DECLARE_MODEL(tunnel_status_event, TUNNEL_STATUS_EVENT)
DECLARE_MODEL(identity_event, IDENTITY_EVENT)
DECLARE_MODEL(services_event, SERVICES_EVENT)

#ifdef __cplusplus
}
#endif

#endif //ZITI_TUNNEL_SDK_C_EVENTS_H
