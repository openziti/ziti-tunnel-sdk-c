#ifndef _lwipopts_h_
#define _lwipopts_h_ 1

#define NO_SYS 1

#define MEM_SIZE              524288      /* the size of the heap memory (1600) */

//#define MEMP_NUM_PBUF       64          /* number of memp struct pbufs (used for PBUF_ROM and PBUF_REF) */

#define MEMP_NUM_TCP_PCB      64          /* simultaneously active TCP connections (5) */
#define MEMP_NUM_TCP_SEG      1024          /* simultaneously queued TCP segments (16) */

#define PBUF_POOL_SIZE        512         /* number of buffers in the pbuf pool (16) */

#define TCP_WND               0xffff     /* size of a TCP window. when using TCP_RCV_SCALE, TCP_WND is the total size with scaling applied (4 * TCP_MSS) */
#define TCP_MSS               16384      /* TCP Maximum segment size (536) */
#define TCP_SND_BUF           TCP_WND     /* TCP sender buffer space in bytes (2 * TCP_MSS) */
#define TCP_SND_QUEUELEN      64          /* TCP sender buffer space in pbufs ((4 * (TCP_SND_BUF) + (TCP_MSS - 1))/(TCP_MSS)) */
// TCP_SNDQUEUELEN_OVERFLOW = 0xffffu - 3
#define TCP_SNDLOWAT          (0xffff-(4*TCP_MSS)-1) /* TCP writable space (bytes). must be less than TCP_SND_BUF. the amount of space which must be available in the TCP snd_buf for select to return writable (combined with TCP_SNDQUEUELOWAT) LWIP_MIN(LWIP_MAX(((TCP_SND_BUF)/2), (2 * TCP_MSS) + 1), (TCP_SND_BUF) - 1) */
#define LWIP_WND_SCALE        1           /* set to 1 to enable window scaling */
#define TCP_RCV_SCALE         8          /* desired scaling factor - shift count in the range of [0..14] */

#define LWIP_SINGLE_NETIF 1

// APIs
#define LWIP_RAW 1
#define LWIP_NETCONN 0
#define LWIP_SOCKET 0

#ifdef _WIN32
#define LWIP_NORAND 1
#endif
// hooks

#define LWIP_HOOK_FILENAME "lwiphooks.h"
#define LWIP_HOOK_IP4_INPUT(pbuf, input_netif) ip4_input_hook((pbuf),(input_netif))
#if 0
#define LWIP_HOOK_TCP_INPACKET_PCB(pcb, hdr, optlen, opt1len, opt2, p) tcp_inpkt_hook((pcb),(hdr),(optlen),(opt1len),(opt2),(p))
#endif
#endif // _lwipopts_h_