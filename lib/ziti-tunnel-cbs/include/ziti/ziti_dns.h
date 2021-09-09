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

#ifndef ZITI_TUNNEL_SDK_C_ZITI_DNS_H
#define ZITI_TUNNEL_SDK_C_ZITI_DNS_H

int ziti_dns_setup(tunneler_context tnlr, const char *dns_addr, const char *dns_cidr);

#endif //ZITI_TUNNEL_SDK_C_ZITI_DNS_H
