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

#include "model/dtos.h"
#include <ziti/ziti_log.h>
#include "ziti/sys/queue.h"
#include <time.h>

struct tnl_identity_s {
    tunnel_identity *id;
    tunnel_service_array *tnl_svc_array;
    LIST_ENTRY(tnl_identity_s) _next;
};

static LIST_HEAD(tnl_identities, tnl_identity_s) tnl_identity_list = LIST_HEAD_INITIALIZER(&tnl_identity_list);

tunnel_identity *find_tunnel_identity(char* identifier) {
    struct tnl_identity_s *tnl_id;
    LIST_FOREACH(tnl_id, &tnl_identity_list, _next) {
        if (strcmp(identifier, tnl_id->id->Identifier) == 0) break;
    }
    if (tnl_id != NULL) {
        return tnl_id->id;
    } else {
        ZITI_LOG(WARN, "ztx[%s] is not found. It may not be active/connected", identifier);
        return NULL;
    }
}

tunnel_identity *get_tunnel_identity(char* identifier) {
    tunnel_identity *id = find_tunnel_identity(identifier);

    if (id != NULL) {
        return id;
    } else {
        struct tnl_identity_s *tnl_id = malloc(sizeof(struct tnl_identity_s));
        tnl_id->id = calloc(1, sizeof(struct tunnel_identity_s));
        tnl_id->id->Identifier = strdup(identifier);
        LIST_INSERT_HEAD(&tnl_identity_list, tnl_id, _next);
        return tnl_id->id;
    }
}

static tunnel_posture_check *getTunnelPostureCheck(ziti_posture_query *pq){
    tunnel_posture_check *pc = calloc(1, sizeof(struct tunnel_posture_check_s));
    pc->Id = strdup(pq->id);
    pc->IsPassing = pq->is_passing;
    pc->QueryType = strdup(pq->query_type);
    pc->Timeout = pq->timeout;
    pc->TimeoutRemaining = pq->timeoutRemaining;
    return pc;
}

static void setTunnelPostureDataTimeout(tunnel_service *tnl_svc, ziti_service *service) {
    int posture_set_idx;
    int minTimeoutRemaining = -1;
    int minTimeout = -1;
    bool hasAccess = false;
    model_map postureCheckMap = {0};

    if (service->posture_query_set != NULL) {

        for (posture_set_idx = 0; service->posture_query_set[posture_set_idx] != 0; posture_set_idx++) {
            int posture_query_idx;

            ziti_posture_query_set *pqs = service->posture_query_set[posture_set_idx];
            if (pqs->policy_type == "Bind") {
                ZITI_LOG(TRACE, "Posture Query set returned a Bind policy: %s [ignored]", pqs->policy_id);
                continue;
            } else {
                ZITI_LOG(TRACE, "Posture Query set returned a %s policy: %s, is_passing %t", pqs->policy_type, pqs->policy_id, pqs->is_passing);
            }

            if (pqs->is_passing) {
                hasAccess = true;
            }

            for (posture_query_idx = 0; service->posture_query_set[posture_set_idx]->posture_queries[posture_query_idx]; posture_query_idx++) {
                ziti_posture_query *pq = service->posture_query_set[posture_set_idx]->posture_queries[posture_query_idx];
                ziti_posture_query *tmp = model_map_get(&postureCheckMap, pq->id);
                if (tmp == NULL) {
                    model_map_set(&postureCheckMap, pq->id, pq);
                }

                int timeoutRemaining = *service->posture_query_set[posture_set_idx]->posture_queries[posture_query_idx]->timeoutRemaining;
                if ((minTimeoutRemaining == -1) || (timeoutRemaining < minTimeoutRemaining)) {
                    minTimeoutRemaining = timeoutRemaining;
                }

                int timeout = service->posture_query_set[posture_set_idx]->posture_queries[posture_query_idx]->timeout;
                if ((minTimeout == -1) || (timeout < minTimeout)) {
                    minTimeout = timeout;
                }
            }
        }
    }

    if (model_map_size(&postureCheckMap) > 0) {
        int idx = 0;
        tnl_svc->PostureChecks = calloc(model_map_size(&postureCheckMap), sizeof(struct tunnel_posture_check_s));
        model_map_iter itr = model_map_iterator(&postureCheckMap);
        while (itr != NULL){
            ziti_posture_query *pq = model_map_it_value(itr);
            tunnel_posture_check *pc = getTunnelPostureCheck(pq);
            tnl_svc->PostureChecks[idx] = pc;
        }
        model_map_clear(&postureCheckMap, (_free_f) free_ziti_posture_query);
    }

    tnl_svc->IsAccessable = hasAccess;
    tnl_svc->Timeout = minTimeout;
    tnl_svc->TimeoutRemaining = minTimeoutRemaining;
    ZITI_LOG(DEBUG, "service[%s] timeout=%d timeoutRemaining=%d", service->name, minTimeout, minTimeoutRemaining);
}


tunnel_service *get_tunnel_service(tunnel_identity* id, ziti_service* zs) {
    struct tunnel_service_s *svc = malloc(sizeof(struct tunnel_service_s));
    svc->Id = strdup(zs->id);
    svc->Name = strdup(zs->name);
    svc->PostureChecks = NULL;
    setTunnelPostureDataTimeout(svc, zs);
    // set correct values below
    svc->OwnsIntercept = true;
    svc->Addresses = NULL;
    svc->Ports = NULL;
    svc->Protocols = NULL;
    return svc;
}

void set_mfa_status(char* identifier, bool mfa_enabled, bool mfa_needed) {
    tunnel_identity *tnl_id = find_tunnel_identity(identifier);
    if (tnl_id != NULL) {
        tnl_id->MfaEnabled = mfa_enabled;
        tnl_id->MfaNeeded = mfa_needed;
        ZITI_LOG(DEBUG, "ztx[%s] mfa enabled : %d, mfa needed : %d ", identifier, mfa_enabled, mfa_needed);
    }
}

void update_mfa_time(char* identifier) {
    tunnel_identity *tnl_id = find_tunnel_identity(identifier);
    if (tnl_id != NULL) {
        uv_timeval64_t now;
        uv_gettimeofday(&now);

        if (tnl_id->MfaLastUpdatedTime == NULL) {
            tnl_id->MfaLastUpdatedTime = malloc(sizeof(timestamp));
        }
        tnl_id->MfaLastUpdatedTime->tv_sec = now.tv_sec;
        tnl_id->MfaLastUpdatedTime->tv_usec = now.tv_usec;
    }
}

// ************** TUNNEL BROADCAST MESSAGES
IMPL_MODEL(tunnel_identity, TUNNEL_IDENTITY)
IMPL_MODEL(tunnel_config, TUNNEL_CONFIG)
IMPL_MODEL(tunnel_metrics, TUNNEL_METRICS)
IMPL_MODEL(tunnel_address, TUNNEL_ADDRESS)
IMPL_MODEL(tunnel_port_range, TUNNEL_PORT_RANGE)
IMPL_MODEL(tunnel_posture_check, TUNNEL_POSTURE_CHECK)
IMPL_MODEL(tunnel_service, TUNNEL_SERVICE)

