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

#ifndef ZITI_TUNNEL_SDK_C_PCAP_H
#define ZITI_TUNNEL_SDK_C_PCAP_H

#include <ziti/netif_driver.h>

/**
 * Open a physical network adapter via Npcap/libpcap as an L2 netif driver.
 *
 * Opens the adapter named by ifname (Windows friendly name, e.g. "Ethernet"),
 * captures all Ethernet frames from it, and delivers them to the tunneler's
 * L2 pipeline.  Outbound frames (from Ziti) are injected via pcap_sendpacket.
 *
 * Requires Npcap (or WinPcap) to be installed and Administrator privileges.
 *
 * @param loop      libuv event loop
 * @param ifname    Windows adapter friendly name (e.g. "Ethernet", "Wi-Fi")
 * @param error     buffer to receive error message on failure
 * @param error_len size of error buffer
 * @return netif_driver on success, NULL on failure
 */
extern netif_driver ziti_pcap_open(struct uv_loop_s *loop, const char *ifname,
                                    char *error, size_t error_len);

#endif /* ZITI_TUNNEL_SDK_C_PCAP_H */
