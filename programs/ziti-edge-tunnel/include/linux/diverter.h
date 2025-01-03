/*
 Copyright 2025 NetFoundry Inc.

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

// support interactions with zfw command line utility

#include <stdint.h>
#include "model/dtos.h"

extern char *diverter_if;
extern bool diverter;
extern bool firewall;

void diverter_init(uint32_t dns_prefix, uint32_t dns_prefix_len, const char *tun_name);
void diverter_quit();
void init_diverter_interface(const char *interface, const char *direction);
void diverter_add_svc(const tunnel_service *svc);
void diverter_remove_svc(const tunnel_service *svc);
void set_diverter(uint32_t dns_prefix, unsigned char dns_prefix_len, const char *tun_name);
void diverter_cleanup();