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

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <net/if.h>

#include <uv.h>

#include "ziti/ziti_log.h"
#include "linux/diverter.h"
#include "../netif_driver/linux/utils.h"

char check_alt[IF_NAMESIZE];
char *diverter_path = "/opt/openziti/bin";
char zfw_path[PATH_MAX];
char *tc_ingress_object = "zfw_tc_ingress.o";
char *tc_egress_object = "zfw_tc_outbound_track.o";
char *xdp_ingress_object = "zfw_xdp_tun_ingress.o";

char *diverter_if = NULL;
bool diverter = false;
bool firewall = false;

void diverter_init(uint32_t dns_prefix, uint32_t dns_prefix_len, const char *tun_name) {
    if(!diverter && !firewall){
        diverter_if = getenv("ZITI_DIVERTER");
        if(diverter_if && strlen(diverter_if)){
            diverter = true;
        }
        char *zifi_firewall = getenv("ZITI_FIREWALL");
        if(zifi_firewall && strlen(zifi_firewall)){
            diverter = true;
            firewall = true;
            diverter_if = getenv("ZITI_FIREWALL");
        }
    }
    char *diverter_env_path = getenv("ZFW_OBJECT_PATH");
    if(diverter_env_path && strlen(diverter_env_path)){
        diverter_path = diverter_env_path;
        snprintf(zfw_path, sizeof(zfw_path), "%s/%s", diverter_env_path, "zfw");
    }else{
        snprintf(zfw_path, sizeof(zfw_path), "%s/%s", diverter_path, "zfw");
    }
    if(diverter && tun_name){
        if(!firewall){
            diverter_quit();
        }
        if (is_executable(zfw_path)){
            int count = 0;
            char *interface = strtok(diverter_if,",");
            while(interface != NULL){
                uint32_t idx = if_nametoindex(interface);
                if (!idx)
                {
                    ZITI_LOG(WARN,"Diverter interface not found: %s", interface);
                    interface = strtok(NULL,",");
                    continue;
                }
                if(if_indextoname(idx, check_alt)){
                    interface = check_alt;
                }
                init_diverter_interface(interface, "ingress");
                init_diverter_interface(interface, "egress");
                interface = strtok(NULL,",");
                count++;
            }
            if(count){
                set_diverter(dns_prefix, dns_prefix_len, tun_name);
            }else{
                ZITI_LOG(ERROR,"No valid diverter interfaces found");
                exit(1);
            }
        }else{
            ZITI_LOG(ERROR, "Diverter binary not found");
            exit(1);
        }
    }
}

static void diverter_update(const char *ip, uint8_t prefix_len, uint16_t lowport, uint16_t highport, const char *protocol, const char *service_id, const char *action) {
    int rndm;
    uv_random(NULL, NULL, &rndm, sizeof(rndm), 0, NULL);
    unsigned short random_port = 1024 + rndm % (65535 - 1023);
    // called while uv loop is running, so queue the command to prevent i/o stalls
    queue_command("%s %s -c %s -m %d -l %d -h %d -t %d -p %s -s %s", zfw_path, action, ip, prefix_len, lowport, highport, random_port, protocol, service_id);
}

void diverter_quit() {
    run_command("%s -Q", zfw_path);
}

void init_diverter_interface(const char *interface, const char *direction) {
    // run_command is ok here because the uv loop is not yet running when this is called
    const char *obj = (strcmp(direction, "ingress") == 0 ? tc_ingress_object : tc_egress_object);
    int ec = run_command("%s -X %s -O %s/%s -z %s", zfw_path, interface, diverter_path, obj, direction);
    if (ec != 0) {
        ZITI_LOG(WARN, "zfw -X failed");
        return;
    }

    // set tun mode
    ec = run_command("%s -T %s", zfw_path, interface);
    if (ec != 0) {
        ZITI_LOG(WARN, "zfw -T failed");
        return;
    }

    // enable ipv6
    ec = run_command("%s -6 %s", zfw_path, interface);
    if (ec != 0) {
        ZITI_LOG(WARN, "zfw -6 failed");
        return;
    }

    // pass non-tuple
    if (!firewall) {
        run_command("%s -q %s", zfw_path, interface);
    }
}

static void bind_diverter_route(const char *ip, uint8_t prefix_len) {
    // called while uv loop is running, so queue the command to prevent i/o stalls
    queue_command("%s -B %s -m %d", zfw_path, ip, prefix_len);
}

static void unbind_diverter_route(const char *ip, uint8_t prefix_len) {
    // called while uv loop is running, so queue the command to prevent i/o stalls
    queue_command("%s -J %s -m %d", zfw_path, ip, prefix_len);
}

void diverter_add_svc(const tunnel_service *svc) {
    if(svc && diverter){
        if(svc->Permissions.Dial){
            for(int x = 0; svc->Addresses && (svc->Addresses[x] != NULL); x++){
                if(!svc->Addresses[x]->IsHost){
                    for(int i =  0; (svc->Ports != NULL) && (svc->Ports[i] != NULL); i++){
                        for(int j =  0; (svc->Protocols != NULL) && (svc->Protocols[j] != NULL); j++){
                            if((svc->AllowedSourceAddresses && svc->AllowedSourceAddresses[0] != NULL) || firewall){
                                diverter_update(svc->Addresses[x]->IP, svc->Addresses[x]->Prefix, svc->Ports[i]->Low, svc->Ports[i]->High, svc->Protocols[j], svc->Id, "-I");
                            }
                        }
                    }

                }
            }
        }
        else if(svc->Permissions.Bind){
            for(int x = 0; svc->AllowedSourceAddresses && (svc->AllowedSourceAddresses[x] != NULL); x++){
                if(!svc->AllowedSourceAddresses[x]->IsHost){
                    bind_diverter_route(svc->AllowedSourceAddresses[x]->IP, svc->AllowedSourceAddresses[x]->Prefix);
                }
            }
        }
    }
}
void diverter_remove_svc(const tunnel_service *svc) {
    if(svc && diverter){
        if(svc->Permissions.Bind){
            for(int x = 0; svc->AllowedSourceAddresses && (svc->AllowedSourceAddresses[x] != NULL); x++){
                if(!svc->AllowedSourceAddresses[x]->IsHost){
                    unbind_diverter_route(svc->AllowedSourceAddresses[x]->IP, svc->AllowedSourceAddresses[x]->Prefix);
                }
            }
        }
        if(svc->Permissions.Dial){
            for(int x = 0; svc->Addresses && (svc->Addresses[x] != NULL); x++){
                if(!svc->Addresses[x]->IsHost){
                    for(int i =  0; (svc->Ports != NULL) && (svc->Ports[i] != NULL); i++){
                        for(int j =  0; (svc->Protocols != NULL) && (svc->Protocols[j] != NULL); j++){
                            if((svc->AllowedSourceAddresses && svc->AllowedSourceAddresses[0] != NULL) || firewall){
                                diverter_update(svc->Addresses[x]->IP, svc->Addresses[x]->Prefix, svc->Ports[i]->Low, svc->Ports[i]->High, svc->Protocols[j], svc->Id, "-D");
                            }
                        }
                    }

                }
            }
        }
    }
}

static void diverter_binding_flush() {
    // called by exit handler, so run_command is appropriate
    run_command("%s -F -j", zfw_path);
}

static void diverter_ingress_flush() {
    // called by exit handler, so run_command is appropriate
    run_command("%s -F -z ingress", zfw_path);
}

static void setup_xdp(const char *tun_name) {
    // run_command is ok here because the uv loop is not yet running when this is called
    run_command("/usr/sbin/ip link set %s xdpgeneric obj %s/%s sec xdp_redirect", tun_name, diverter_path, xdp_ingress_object);
}

static void add_user_rules() {
    // called by exit handler, so run_command is appropriate
    run_command("%s -A", zfw_path);
}

static void disable_firewall() {
    // run_command is ok here because the uv loop is not yet running when this is called
    run_command("%s -I -c 0.0.0.0 -m 0 -l 1 -h 65535 -t 0 -p tcp", zfw_path);
    run_command("%s -I -c 0.0.0.0 -m 0 -l 1 -h 65535 -t 0 -p udp", zfw_path);
    run_command("%s -I -c :: -m 0 -l 1 -h 65535 -t 0 -p tcp", zfw_path);
    run_command("%s -I -c :: -m 0 -l 1 -h 65535 -t 0 -p udp", zfw_path);
}

static void pass_dns_range(uint32_t dns_prefix, uint8_t dns_prefix_len) {
    // run_command is ok here because the uv loop is not yet running when this is called
    char prefix[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &dns_prefix, prefix, INET_ADDRSTRLEN);
    run_command("%s -I -c %s -m %d -l 1 -h 65535 -t 65535 -p tcp", zfw_path, prefix, dns_prefix_len);
    run_command("%s -I -c %s -m %d -l 1 -h 65535 -t 65535 -p udp", zfw_path, prefix, dns_prefix_len);
}

void set_diverter(uint32_t dns_prefix, uint8_t dns_prefix_len, const char *tun_name)
{
    if (!firewall) {
        ZITI_LOG(INFO,"Starting ziti-edge-tunnel in diverter mode");
    } else {
        ZITI_LOG(INFO,"Starting ziti-edge-tunnel in diverter firewall mode");
    }
    if (!firewall) {
        disable_firewall();
    } else {
        if (is_executable(zfw_path)) {
            ZITI_LOG(INFO,"loading user defined FW rules");
            add_user_rules();
        } else {
            ZITI_LOG(DEBUG, "Diverter user defined FW rules not found");
        }
        pass_dns_range(dns_prefix, dns_prefix_len);
    }
    setup_xdp(tun_name);
}

void diverter_cleanup(void) {
    if (diverter && !firewall) {
        diverter_binding_flush();
        diverter_quit();
    } else if (firewall) {
        diverter_binding_flush();
        diverter_ingress_flush();
        add_user_rules();
    }
}