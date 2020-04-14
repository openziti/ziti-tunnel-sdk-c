#ifndef _lwipopts_h_
#define _lwipopts_h_ 1

#define NO_SYS 1

#define MEM_SIZE 16384

//#define MEMP_NUM_PBUF 64

#define MEMP_NUM_TCP_SEG                64//16

//#define LWIP_DNS 1?

#define TCP_WND                         0xffff //(4 * TCP_MSS)
#define TCP_MSS                         4096 //536
#define TCP_SND_BUF                     TCP_WND //(2 * TCP_MSS)
#define TCP_SND_QUEUELEN                ((4 * (TCP_SND_BUF) + (TCP_MSS - 1))/(TCP_MSS))
#define LWIP_WND_SCALE                  1
#define TCP_RCV_SCALE                   14

#define LWIP_SINGLE_NETIF 1

#define PBUF_POOL_SIZE 64

// APIs
#define LWIP_RAW 1
#define LWIP_NETCONN 0
#define LWIP_SOCKET 0

// hooks

#define LWIP_HOOK_FILENAME "lwiphooks.h"
#define LWIP_HOOK_IP4_INPUT(pbuf, input_netif) ip4_input_hook((pbuf),(input_netif))
#if 0
#define LWIP_HOOK_TCP_INPACKET_PCB(pcb, hdr, optlen, opt1len, opt2, p) tcp_inpkt_hook((pcb),(hdr),(optlen),(opt1len),(opt2),(p))
#endif
#endif // _lwipopts_h_