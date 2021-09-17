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
static const char* CFG_INTERCEPT_V1 = "intercept.v1";
static const char* CFG_ZITI_TUNNELER_CLIENT_V1 = "ziti-tunneler-client.v1";

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
        tnl_id->id->Services = NULL;
        LIST_INSERT_HEAD(&tnl_identity_list, tnl_id, _next);
        return tnl_id->id;
    }
}

void add_or_remove_services_from_tunnel(tunnel_identity *id, tunnel_service_array added_services, tunnel_service_array removed_services) {

    model_map updates = {0};

    int idx = 0;
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
                free_tunnel_service(rem_svc);
                free(rem_svc);
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
        id->Services = calloc(model_map_size(&updates), sizeof(struct tunnel_service_s));
    } else {
        free(id->Services);
        id->Services = calloc(model_map_size(&updates), sizeof(struct tunnel_service_s));
    }
    model_map_iter it = model_map_iterator(&updates);
    idx=0;
    while(it != NULL) {
        id->Services[idx++] = model_map_it_value(it);
        it = model_map_it_next(it);
    };

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
                ZITI_LOG(TRACE, "Posture Query set returned a %s policy: %s, is_passing %d", pqs->policy_type, pqs->policy_id, pqs->is_passing);
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
    const char* intercept_v1_config = ziti_service_get_raw_config(service, CFG_INTERCEPT_V1);
    tunnel_address_array tnl_addr_arr;
    string_array protocols = NULL;
    tunnel_port_range_array tnl_port_range_arr;
    if (intercept_v1_config != NULL && strlen(intercept_v1_config) > 0) {
        ZITI_LOG(TRACE, "intercept.v1: %s", intercept_v1_config);
        ziti_intercept_cfg_v1 cfg_v1;
        parse_ziti_intercept_cfg_v1(&cfg_v1, intercept_v1_config, strlen(intercept_v1_config));

        // set address
        tnl_addr_arr = calloc(sizeof(cfg_v1.addresses), sizeof(tunnel_address *)); // todo sizeof(cfg_v1.addresses) does not yield the number of port addresses.
        int address_idx;
        for(address_idx=0; cfg_v1.addresses[address_idx]; address_idx++) {
            char* addr = cfg_v1.addresses[address_idx];
            tnl_addr_arr[address_idx] = to_address(addr);
        }

        // set protocols
        protocols = cfg_v1.protocols;

        // set ports
        tnl_port_range_arr = calloc(sizeof(cfg_v1.port_ranges), sizeof(tunnel_port_range *)); // todo sizeof(cfg_v1.port_ranges) does not yield the number of port ranges.
        int port_idx;
        for(port_idx=0; cfg_v1.port_ranges[port_idx]; port_idx++) {
            tnl_port_range_arr[port_idx] = getTunnelPortRange(cfg_v1.port_ranges[port_idx]);
        }
    } else {
        const char* zt_client_v1_config = ziti_service_get_raw_config(service, CFG_ZITI_TUNNELER_CLIENT_V1);
        ZITI_LOG(TRACE, "ziti-tunneler-client.v1: %s", zt_client_v1_config);
        ziti_client_cfg_v1 zt_client_cfg_v1;
        parse_ziti_client_cfg_v1(&zt_client_cfg_v1, zt_client_v1_config, strlen(zt_client_v1_config));

        // set tunnel address
        tnl_addr_arr = calloc(2, sizeof(tunnel_address *));
        tnl_addr_arr[0] = to_address(zt_client_cfg_v1.hostname);

        // set protocols
        protocols = calloc(3, sizeof(char*));
        int idx=0;
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

tunnel_service *get_tunnel_service(tunnel_identity* id, ziti_service* zs) {
    struct tunnel_service_s *svc = malloc(sizeof(struct tunnel_service_s));
    svc->Id = strdup(zs->id);
    svc->Name = strdup(zs->name);
    svc->PostureChecks = NULL;
    svc->OwnsIntercept = true;
    setTunnelPostureDataTimeout(svc, zs);
    setTunnelServiceAddress(svc, zs);
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

