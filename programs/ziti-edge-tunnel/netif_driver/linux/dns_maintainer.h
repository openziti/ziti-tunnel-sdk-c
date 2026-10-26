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

// keeps the system's DNS configuration pointed at the ziti resolver on the tun device

#ifndef ZITI_TUNNELER_SDK_DNS_MAINTAINER_H
#define ZITI_TUNNELER_SDK_DNS_MAINTAINER_H

#include <stdint.h>
#include <uv.h>
#include <ziti/netif_driver.h>

void dns_maintainer_init(uv_loop_t *loop, const char *tun_name, uint32_t dns_ip);

// netif_driver hooks
void dns_maintainer_domains_changed(netif_handle dev, uv_loop_t *loop);
void dns_maintainer_refresh_fallback(netif_handle dev, uv_loop_t *loop);

#endif // ZITI_TUNNELER_SDK_DNS_MAINTAINER_H
