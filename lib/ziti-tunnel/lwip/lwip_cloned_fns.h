#ifndef ZITI_TUNNELER_SDK_LWIP_CLONED_FNS_H
#define ZITI_TUNNELER_SDK_LWIP_CLONED_FNS_H

#include "lwip/tcp.h"

extern void tunneler_tcp_input(struct pbuf *p);
extern void tunneler_tcp_parseopt(struct tcp_pcb *pcb);

#endif //ZITI_TUNNELER_SDK_LWIP_CLONED_FNS_H