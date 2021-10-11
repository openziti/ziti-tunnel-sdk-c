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

#include "model/dtos.h"
#include <ziti/ziti_log.h>
#include <time.h>
#include "model/events.h"

model_map tnl_identity_map = {0};
static const char* CFG_INTERCEPT_V1 = "intercept.v1";
static const char* CFG_ZITI_TUNNELER_CLIENT_V1 = "ziti-tunneler-client.v1";
static tunnel_status tnl_status;

tunnel_identity *find_tunnel_identity(const char* identifier) {
    tunnel_identity *tnl_id = model_map_get(&tnl_identity_map, identifier);
    if (tnl_id != NULL) {
        return tnl_id;
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
        tunnel_identity *tnl_id = calloc(1, sizeof(struct tunnel_identity_s));
        tnl_id->Identifier = strdup(identifier);
        model_map_set(&tnl_identity_map, identifier, tnl_id);
        return tnl_id;
    }
}

void set_mfa_timeout(tunnel_identity *tnl_id) {
    if (tnl_id->Services != NULL) {
        int mfa_min_timeout = -1;
        int mfa_min_timeout_rem = -1;
        int mfa_max_timeout = -1;
        int mfa_max_timeout_rem = -1;
        bool no_timeout_svc = false;
        bool no_timeout_svc_rem = false;
        for (int svc_idx = 0; tnl_id->Services[svc_idx] != 0; svc_idx++) {
            tunnel_service *tnl_svc = tnl_id->Services[svc_idx];

            if (tnl_svc->Timeout > -1) {
                if (mfa_min_timeout == -1 || mfa_min_timeout > tnl_svc->Timeout) {
                    mfa_min_timeout = tnl_svc->Timeout;
                }
                if (mfa_max_timeout == -1 || mfa_max_timeout < tnl_svc->Timeout) {
                    mfa_max_timeout = tnl_svc->Timeout;
                }
            } else {
                no_timeout_svc = true;
            }
            if (tnl_svc->TimeoutRemaining > -1) {
                if (mfa_min_timeout_rem == -1 || mfa_min_timeout_rem > tnl_svc->TimeoutRemaining) {
                    mfa_min_timeout_rem = tnl_svc->TimeoutRemaining;
                }
                if (mfa_max_timeout_rem == -1 || mfa_max_timeout_rem < tnl_svc->TimeoutRemaining) {
                    mfa_max_timeout_rem = tnl_svc->TimeoutRemaining;
                }
            } else {
                no_timeout_svc_rem = true;
            }

        }
        if (no_timeout_svc) {
            mfa_max_timeout = -1;
        }
        if (no_timeout_svc_rem) {
            mfa_max_timeout_rem = -1;
        }

        tnl_id->MfaMaxTimeout = mfa_max_timeout;
        tnl_id->MfaMaxTimeoutRem = mfa_max_timeout_rem;
        tnl_id->MaxTimeoutRemInSvcEvent = mfa_max_timeout_rem;
        tnl_id->MfaMinTimeout = mfa_min_timeout;
        tnl_id->MfaMinTimeoutRem = mfa_min_timeout_rem;
        tnl_id->MinTimeoutRemInSvcEvent = mfa_min_timeout_rem;
    }

}

void add_or_remove_services_from_tunnel(tunnel_identity *id, tunnel_service_array added_services, tunnel_service_array removed_services) {

    int idx;
    model_map updates = {0};

    // add services from tunnel id to map
    if (id->Services != NULL) {
        for (idx =0; id->Services[idx]; idx++) {
            tunnel_service *svc = id->Services[idx];
            model_map_set(&updates, svc->Name, svc);
        }
    }

    // remove services from map
    if (removed_services != NULL) {
        for(idx=0; removed_services[idx]; idx++){
            tunnel_service *svc = removed_services[idx];
            tunnel_service *rem_svc = model_map_get(&updates, svc->Name);
            if (rem_svc != NULL) {
                model_map_remove(&updates, rem_svc->Name);
            }
        }
    }

    //add services to map
    if (added_services != NULL) {
        for(idx=0; added_services[idx]; idx++){
            tunnel_service *svc = added_services[idx];
            model_map_set(&updates, svc->Name, svc);
        }
    }

    // reallocate when new event comes, we need to maintain the whole list of services in tunnel_identity
    if (id->Services == NULL) {
        id->Services = calloc(model_map_size(&updates) + 1, sizeof(struct tunnel_service_s));
    } else {
        free(id->Services);
        id->Services = calloc(model_map_size(&updates) + 1, sizeof(struct tunnel_service_s));
    }
    model_map_iter it = model_map_iterator(&updates);
    idx=0;
    while(it != NULL) {
        id->Services[idx++] = model_map_it_value(it);
        it = model_map_it_next(it);
    }
    set_mfa_timeout(id);
    uv_timeval64_t now;
    uv_gettimeofday(&now);
    if (id->ServiceUpdatedTime == NULL) {
        id->ServiceUpdatedTime = malloc(sizeof(timestamp));
    }
    id->ServiceUpdatedTime->tv_sec = now.tv_sec;
    id->ServiceUpdatedTime->tv_usec = now.tv_usec;

}

static tunnel_posture_check *getTunnelPostureCheck(ziti_posture_query *pq){
    tunnel_posture_check *pc = calloc(1, sizeof(struct tunnel_posture_check_s));
    pc->Id = strdup(pq->id);
    pc->IsPassing = pq->is_passing;
    pc->QueryType = strdup(pq->query_type);
    pc->Timeout = pq->timeout;
    pc->TimeoutRemaining = *pq->timeoutRemaining;
    return pc;
}

static void setTunnelPostureDataTimeout(tunnel_service *tnl_svc, ziti_service *service) {
    int minTimeoutRemaining = -1;
    int minTimeout = -1;
    bool hasAccess = false;
    model_map postureCheckMap = {0};

    ziti_posture_query_set *pqs;
    const char *key;
    MODEL_MAP_FOREACH(key, pqs, &service->posture_query_map) {

        if (pqs->policy_type == "Bind") {
            ZITI_LOG(TRACE, "Posture Query set returned a Bind policy: %s [ignored]", pqs->policy_id);
            continue;
        } else {
            ZITI_LOG(TRACE, "Posture Query set returned a %s policy: %s, is_passing %d", pqs->policy_type, pqs->policy_id, pqs->is_passing);
        }

        if (pqs->is_passing) {
            hasAccess = true;
        }

        for (int posture_query_idx = 0; pqs->posture_queries[posture_query_idx]; posture_query_idx++) {
            ziti_posture_query *pq = pqs->posture_queries[posture_query_idx];
            ziti_posture_query *tmp = model_map_get(&postureCheckMap, pq->id);
            if (tmp == NULL) {
                model_map_set(&postureCheckMap, pq->id, pq);
            }

            int timeoutRemaining = *pqs->posture_queries[posture_query_idx]->timeoutRemaining;
            if ((minTimeoutRemaining == -1) || (timeoutRemaining < minTimeoutRemaining)) {
                minTimeoutRemaining = timeoutRemaining;
            }

            int timeout = pqs->posture_queries[posture_query_idx]->timeout;
            if ((minTimeout == -1) || (timeout < minTimeout)) {
                minTimeout = timeout;
            }
        }
    }

    if (model_map_size(&postureCheckMap) > 0) {
        int idx = 0;
        tnl_svc->PostureChecks = calloc(model_map_size(&postureCheckMap) + 1, sizeof(struct tunnel_posture_check_s));
        model_map_iter itr = model_map_iterator(&postureCheckMap);
        while (itr != NULL){
            ziti_posture_query *pq = model_map_it_value(itr);
            tunnel_posture_check *pc = getTunnelPostureCheck(pq);
            tnl_svc->PostureChecks[idx] = pc;
            itr = model_map_it_next(itr);
        }
    }

    tnl_svc->IsAccessable = hasAccess;
    tnl_svc->Timeout = minTimeout;
    tnl_svc->TimeoutRemaining = minTimeoutRemaining;
    ZITI_LOG(DEBUG, "service[%s] timeout=%d timeoutRemaining=%d", service->name, minTimeout, minTimeoutRemaining);
}

static tunnel_address *to_address(string hostOrIPOrCIDR) {
    tunnel_address *tnl_address = calloc(1, sizeof(struct tunnel_address_s));
    tnl_address->IsHost = false;
    tnl_address->Prefix = 0;

    struct in_addr ip;
    int err = uv_inet_pton(AF_INET, hostOrIPOrCIDR, &ip);
    if (err == 0) {
        tnl_address->IP = calloc(INET_ADDRSTRLEN+1, sizeof(char));
        uv_inet_ntop(AF_INET, &ip, tnl_address->IP, INET_ADDRSTRLEN);
        tnl_address->HostName = NULL;
        ZITI_LOG(TRACE, "IP address: %s", ip);
    } else {
        tnl_address->IsHost = true;
        tnl_address->IP = NULL;
        tnl_address->HostName = hostOrIPOrCIDR;
        ZITI_LOG(TRACE, "Hostname: %s", hostOrIPOrCIDR);
    }
    // find CIDR
    return tnl_address;
}

tunnel_port_range *getTunnelPortRange(ziti_port_range *zpr){
    tunnel_port_range *tpr = calloc(1, sizeof(struct tunnel_port_range_s));
    tpr->High = zpr->high;
    tpr->Low = zpr->low;
    return tpr;
}

static void setTunnelServiceAddress(tunnel_service *tnl_svc, ziti_service *service) {
    const char* cfg_json = ziti_service_get_raw_config(service, CFG_INTERCEPT_V1);
    tunnel_address_array tnl_addr_arr = NULL;
    string_array protocols = NULL;
    tunnel_port_range_array tnl_port_range_arr;
    if (cfg_json != NULL && strlen(cfg_json) > 0) {
        ZITI_LOG(TRACE, "intercept.v1: %s", cfg_json);
        ziti_intercept_cfg_v1 cfg_v1;
        parse_ziti_intercept_cfg_v1(&cfg_v1, cfg_json, strlen(cfg_json));

        // set address
        int idx = 0;
        for(idx = 0; cfg_v1.addresses[idx]; idx++) {
            // do nothing
        }
        tnl_addr_arr = calloc(idx+1, sizeof(tunnel_address *));
        for(int address_idx=0; cfg_v1.addresses[address_idx]; address_idx++) {
            char* addr = cfg_v1.addresses[address_idx];
            tnl_addr_arr[address_idx] = to_address(addr);
        }

        // set protocols
        protocols = cfg_v1.protocols;

        // set ports
        for(idx = 0; cfg_v1.port_ranges[idx]; idx++) {
            // do nothing
        }
        tnl_port_range_arr = calloc(idx+1, sizeof(tunnel_port_range *));
        for(int port_idx = 0; cfg_v1.port_ranges[port_idx]; port_idx++) {
            tnl_port_range_arr[port_idx] = getTunnelPortRange(cfg_v1.port_ranges[port_idx]);
        }
    }  else if ((cfg_json = ziti_service_get_raw_config(service, CFG_ZITI_TUNNELER_CLIENT_V1)) != NULL) {
        ZITI_LOG(TRACE, "ziti-tunneler-client.v1: %s", cfg_json);
        ziti_client_cfg_v1 zt_client_cfg_v1;
        parse_ziti_client_cfg_v1(&zt_client_cfg_v1, cfg_json, strlen(cfg_json));

        // set tunnel address
        tnl_addr_arr = calloc(2, sizeof(tunnel_address *));
        tnl_addr_arr[0] = to_address(zt_client_cfg_v1.hostname);

        // set protocols
        protocols = calloc(3, sizeof(char *));
        int idx = 0;
        protocols[idx++] = strdup("TCP");
        protocols[idx] = strdup("UDP");

        // set port range
        // set ports
        tnl_port_range_arr = calloc(2, sizeof(tunnel_port_range *));
        tunnel_port_range *tpr = calloc(1, sizeof(tunnel_port_range));
        tpr->Low = zt_client_cfg_v1.port;
        tpr->High = zt_client_cfg_v1.port;
        tnl_port_range_arr[0] = tpr;
    }
    if (tnl_addr_arr != NULL) {
        tnl_svc->Addresses = tnl_addr_arr;
        tnl_svc->Ports = tnl_port_range_arr;
    }

    tnl_svc->Protocols = protocols;
}

tunnel_service *find_tunnel_service(tunnel_identity* id, char* svc_id) {
    int idx = 0;
    tunnel_service *svc = NULL;
    if (id->Services != NULL) {
        for (idx =0; id->Services[idx]; idx++) {
            svc = id->Services[idx];
            if (strcmp(svc->Id, svc_id) == 0) {
                break;
            }
        }
    }
    return svc;
}

tunnel_service *get_tunnel_service(tunnel_identity* id, ziti_service* zs) {
    struct tunnel_service_s *svc = calloc(1, sizeof(struct tunnel_service_s));
    svc->Id = strdup(zs->id);
    svc->Name = strdup(zs->name);
    svc->PostureChecks = NULL;
    svc->OwnsIntercept = true;
    setTunnelPostureDataTimeout(svc, zs);
    setTunnelServiceAddress(svc, zs);
    return svc;
}

tunnel_identity_array get_tunnel_identities() {
    const char *id;
    tunnel_identity *tnl_id;
    tunnel_identity_array tnl_id_arr = calloc(model_map_size(&tnl_identity_map) + 1, sizeof(tunnel_identity*)); // todo this is leaked

    int idx = 0;
    MODEL_MAP_FOREACH(id, tnl_id, &tnl_identity_map) {
        tnl_id_arr[idx++] = tnl_id;
    }

    return tnl_id_arr;
}

int get_remaining_timeout(int timeout, int timeout_rem, tunnel_identity *tnl_id) {

    if (timeout <= 0 || timeout_rem <= 0 || tnl_id->MfaLastUpdatedTime == NULL || tnl_id->ServiceUpdatedTime == NULL) {
        return timeout_rem;
    }

    int timeout_remaining = 0;
    uv_timeval64_t now;
    uv_gettimeofday(&now);

    // calculate effective timeout remaining from last mfa or service update time
    if (tnl_id->MfaLastUpdatedTime->tv_sec > tnl_id->ServiceUpdatedTime->tv_sec) {
        //calculate svc remaining timeout
        int elapsed_time = now.tv_sec - tnl_id->MfaLastUpdatedTime->tv_sec;
        if ((timeout - elapsed_time) < 0) {
            timeout_remaining = 0;
        } else {
            timeout_remaining = timeout - elapsed_time;
        }
    } else {
        //calculate svc remaining timeout
        int elapsed_time = now.tv_sec - tnl_id->ServiceUpdatedTime->tv_sec;
        if ((timeout_rem - elapsed_time) < 0) {
            timeout_remaining = 0;
        } else {
            timeout_remaining = timeout_rem - elapsed_time;
        }
    }
    return timeout_remaining;
}

void set_mfa_timeout_rem(tunnel_identity *tnl_id) {

    if ((tnl_id->MfaMinTimeoutRem > -1 || tnl_id->MfaMaxTimeoutRem > -1) && tnl_id->Services != NULL ) {
        for (int svc_idx = 0 ; tnl_id->Services[svc_idx]; svc_idx++ ) {
            tunnel_service *tnl_svc = tnl_id->Services[svc_idx];
            int svc_timeout = -1;
            int svc_timeout_rem = -1;
            if (tnl_svc->TimeoutRemaining > -1 && tnl_svc->PostureChecks != NULL ) {
                // fetch service timeout and timeout remaining from the posture checks
                for (int pc_idx = 0; tnl_svc->PostureChecks[pc_idx]; pc_idx++) {
                    tunnel_posture_check *pc = tnl_svc->PostureChecks[pc_idx];
                    if (svc_timeout == -1 || svc_timeout > pc->Timeout) {
                        svc_timeout = pc->Timeout;
                    }
                    if (svc_timeout_rem == -1 || svc_timeout_rem > pc->TimeoutRemaining) {
                        svc_timeout_rem = pc->TimeoutRemaining;
                    }
                }

                tnl_svc->TimeoutRemaining = get_remaining_timeout(svc_timeout, svc_timeout_rem, tnl_id);
            }
        }

        if (tnl_id->MfaMinTimeoutRem > -1) {
            tnl_id->MfaMinTimeoutRem = get_remaining_timeout(tnl_id->MfaMinTimeout, tnl_id->MinTimeoutRemInSvcEvent, tnl_id);
        }
        if (tnl_id->MfaMaxTimeoutRem > -1) {
            tnl_id->MfaMaxTimeoutRem = get_remaining_timeout(tnl_id->MfaMaxTimeout, tnl_id->MaxTimeoutRemInSvcEvent, tnl_id);
        }
        if (tnl_id->MfaMaxTimeoutRem == 0 && tnl_id->MfaEnabled ) {
            tnl_id->MfaNeeded = true;
        }
    }

}

tunnel_status *get_tunnel_status() {
    if (tnl_status.StartTime.tv_sec == 0) {
        tnl_status.Active = false;
        tnl_status.Duration = 0;
        uv_timeval64_t now;
        uv_gettimeofday(&now);
        tnl_status.StartTime.tv_sec = now.tv_sec;
        tnl_status.StartTime.tv_usec = now.tv_usec;
    } else {
        uv_timeval64_t now;
        uv_gettimeofday(&now);
        uint64_t start_time_in_millis = (tnl_status.StartTime.tv_sec * 1000) + (tnl_status.StartTime.tv_usec / 1000);
        uint64_t current_time_in_millis = (now.tv_sec * 1000) + (now.tv_usec / 1000);
        tnl_status.Duration = (int)(current_time_in_millis - start_time_in_millis);
    }

    if (tnl_status.Identities) free(tnl_status.Identities);
    tnl_status.Identities = get_tunnel_identities();

    if (tnl_status.Identities != NULL) {
        for (int id_idx = 0; tnl_status.Identities[id_idx] != 0; id_idx++) {
            set_mfa_timeout_rem(tnl_status.Identities[id_idx]);
            tnl_status.Identities[id_idx]->Notified = false;
        }
    }

    return &tnl_status;
}

void set_mfa_status(char* identifier, bool mfa_enabled, bool mfa_needed) {
    tunnel_identity *tnl_id = find_tunnel_identity(identifier);
    if (tnl_id != NULL) {
        tnl_id->MfaEnabled = mfa_enabled;
        tnl_id->MfaNeeded = mfa_needed;
        tnl_id->Notified = false;
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
IMPL_MODEL(tunnel_status, TUNNEL_STATUS)
