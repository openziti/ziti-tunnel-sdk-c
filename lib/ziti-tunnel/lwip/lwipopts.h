#ifndef _lwipopts_h_
#define _lwipopts_h_ 1

#define NO_SYS 1

#ifndef MEM_SIZE
#define MEM_SIZE              524288      /* the size of the heap memory (1600) */
#endif

#if SCAREY_DEBUGGING_LWIP
#define MEMP_OVERFLOW_CHECK   2           /* reserves bytes before and after each memp element in every pool and fills it with a prominent default value */
#define MEMP_SANITY_CHECK     1           /* run a sanity check after each mem_free() to make sure that the linked list of heap elements is not corrupted */
//#define LWIP_ALLOW_MEM_FREE_FROM_OTHER_CONTEXT 0
#endif
//#define MEMP_NUM_PBUF       64          /* number of memp struct pbufs (used for PBUF_ROM and PBUF_REF) */

#ifndef MEMP_NUM_UDP_PCB
#define MEMP_NUM_UDP_PCB      16          /* simultaneously active UDP "connections" (4) */
#endif
#ifndef MEMP_NUM_TCP_PCB
#define MEMP_NUM_TCP_PCB      64          /* simultaneously active TCP connections (5) */
#endif
#ifndef MEMP_NUM_TCP_SEG
#define MEMP_NUM_TCP_SEG      1024        /* simultaneously queued TCP segments (16) */
#endif
#ifndef PBUF_POOL_SIZE
#define PBUF_POOL_SIZE        512         /* number of buffers in the pbuf pool (16) */
#endif

#define TCP_WND               0xffff      /* size of a TCP window. when using TCP_RCV_SCALE, TCP_WND is the total size with scaling applied (4 * TCP_MSS) */
#ifdef TCP_MSS
#undef TCP_MSS  /* cleanup warnings */
#endif
#define TCP_MSS               32768       /* TCP Maximum segment size (536) */
#define TCP_SND_BUF           (2*TCP_MSS) /* TCP sender buffer space in bytes (2 * TCP_MSS) */
#define TCP_SND_QUEUELEN      64          /* TCP sender buffer space in pbufs ((4 * (TCP_SND_BUF) + (TCP_MSS - 1))/(TCP_MSS)) */
// TCP_SNDQUEUELEN_OVERFLOW = 0xffffu - 3
#define TCP_SNDLOWAT          (0xffff-(4*TCP_MSS)-1) /* TCP writable space (bytes). must be less than TCP_SND_BUF. the amount of space which must be available in the TCP snd_buf for select to return writable (combined with TCP_SNDQUEUELOWAT) LWIP_MIN(LWIP_MAX(((TCP_SND_BUF)/2), (2 * TCP_MSS) + 1), (TCP_SND_BUF) - 1) */
#define LWIP_WND_SCALE        1           /* set to 1 to enable window scaling */
#define TCP_RCV_SCALE         14          /* desired scaling factor - shift count in the range of [0..14] */

#define LWIP_SINGLE_NETIF 1               /* avoid some lwip "routing" logic */

#define LWIP_TCP_KEEPALIVE 1
#define TCP_KEEPIDLE_DEFAULT 30000       /* 30 seconds of idle before starting to send KEEPALIVE packets */
#define TCP_KEEPINTVL_DEFAULT 10000      /* 10 seconds interval between KEEPALIVE packets */
#define TCP_KEEPCNT_DEFAULT 3            /* number of missed KEEPALIVE ACKs to consider the client dead */

// APIs
#define LWIP_RAW 1
#define LWIP_NETCONN 0
#define LWIP_SOCKET 0

// protocols
#define LWIP_IPV6 1                       /* enable ipv6 */
#define IPV6_FRAG_COPYHEADER 1            /* avoid assert in lwip code when ipv6 is enabled */

#ifdef _WIN32
#define LWIP_NORAND 1
#define LWIP_NO_UNISTD_H 1
#endif

// hooks
#define LWIP_HOOK_FILENAME "lwiphooks.h"
#define LWIP_HOOK_IP4_INPUT(pbuf, input_netif) ip4_input_hook((pbuf),(input_netif))
#define LWIP_HOOK_IP6_INPUT(pbuf, input_netif) ip6_input_hook((pbuf),(input_netif))

#endif // _lwipopts_h_