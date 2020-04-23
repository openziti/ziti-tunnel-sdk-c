/*
 * copied from deps/lwip/src/core/ipv4/ip4.c
 *
 * This function is installed as an input hook for the ziti tunneler SDK.
 * the only change from the original lwip code is that we do not want to
 * match incoming packets to netifs based on IP address; we just take all
 * packets. Changes from the original lwip code are surrounded by
 * #if !ZITI_TUNNELER_SDK_TAKE_ALL_PACKETS.
 */

/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 */

#include "lwip/opt.h"

#if LWIP_IPV4

#include "lwip/ip.h"
#include "lwip/def.h"
#include "lwip/mem.h"
#include "lwip/ip4_frag.h"
#include "lwip/inet_chksum.h"
#include "lwip/netif.h"
#include "lwip/icmp.h"
#include "lwip/igmp.h"
#include "lwip/priv/raw_priv.h"
#include "lwip/udp.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/autoip.h"
#include "lwip/stats.h"
#include "lwip/prot/iana.h"

#include <string.h>

#ifdef LWIP_HOOK_FILENAME
#include LWIP_HOOK_FILENAME
#endif

int
ip4_input_hook(struct pbuf *p, struct netif *inp)
{
  const struct ip_hdr *iphdr;
  struct netif *netif;
  u16_t iphdr_hlen;
  u16_t iphdr_len;
#if IP_ACCEPT_LINK_LAYER_ADDRESSING || LWIP_IGMP
  int check_ip_src = 1;
#endif /* IP_ACCEPT_LINK_LAYER_ADDRESSING || LWIP_IGMP */
#if LWIP_RAW
  raw_input_state_t raw_status;
#endif /* LWIP_RAW */

  LWIP_ASSERT_CORE_LOCKED();

  IP_STATS_INC(ip.recv);
  MIB2_STATS_INC(mib2.ipinreceives);

  /* identify the IP header */
  iphdr = (struct ip_hdr *)p->payload;
  if (IPH_V(iphdr) != 4) {
    LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_WARNING, ("IP packet dropped due to bad version number %"U16_F"\n", (u16_t)IPH_V(iphdr)));
    ip4_debug_print(p);
    pbuf_free(p);
    IP_STATS_INC(ip.err);
    IP_STATS_INC(ip.drop);
    MIB2_STATS_INC(mib2.ipinhdrerrors);
#if !ZITI_TUNNELER_SDK_TAKE_ALL_PACKETS
    return ERR_OK;
#else
    return 1;
#endif
  }

#if !ZITI_TUNNELER_SDK_TAKE_ALL_PACKETS
#ifdef LWIP_HOOK_IP4_INPUT
  if (LWIP_HOOK_IP4_INPUT(p, inp)) {
    /* the packet has been eaten */
    return ERR_OK;
  }
#endif
#endif

  /* obtain IP header length in bytes */
  iphdr_hlen = IPH_HL_BYTES(iphdr);
  /* obtain ip length in bytes */
  iphdr_len = lwip_ntohs(IPH_LEN(iphdr));

  /* Trim pbuf. This is especially required for packets < 60 bytes. */
  if (iphdr_len < p->tot_len) {
    pbuf_realloc(p, iphdr_len);
  }

  /* header length exceeds first pbuf length, or ip length exceeds total pbuf length? */
  if ((iphdr_hlen > p->len) || (iphdr_len > p->tot_len) || (iphdr_hlen < IP_HLEN)) {
    if (iphdr_hlen < IP_HLEN) {
      LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
                  ("ip4_input: short IP header (%"U16_F" bytes) received, IP packet dropped\n", iphdr_hlen));
    }
    if (iphdr_hlen > p->len) {
      LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
                  ("IP header (len %"U16_F") does not fit in first pbuf (len %"U16_F"), IP packet dropped.\n",
                   iphdr_hlen, p->len));
    }
    if (iphdr_len > p->tot_len) {
      LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
                  ("IP (len %"U16_F") is longer than pbuf (len %"U16_F"), IP packet dropped.\n",
                   iphdr_len, p->tot_len));
    }
    /* free (drop) packet pbufs */
    pbuf_free(p);
    IP_STATS_INC(ip.lenerr);
    IP_STATS_INC(ip.drop);
    MIB2_STATS_INC(mib2.ipindiscards);
#if !ZITI_TUNNELER_SDK_TAKE_ALL_PACKETS
    return ERR_OK;
#else
    return 1;
#endif
  }

  /* verify checksum */
#if CHECKSUM_CHECK_IP
  IF__NETIF_CHECKSUM_ENABLED(inp, NETIF_CHECKSUM_CHECK_IP) {
    if (inet_chksum(iphdr, iphdr_hlen) != 0) {

      LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
                  ("Checksum (0x%"X16_F") failed, IP packet dropped.\n", inet_chksum(iphdr, iphdr_hlen)));
      ip4_debug_print(p);
      pbuf_free(p);
      IP_STATS_INC(ip.chkerr);
      IP_STATS_INC(ip.drop);
      MIB2_STATS_INC(mib2.ipinhdrerrors);
#if !ZITI_TUNNELER_SDK_TAKE_ALL_PACKETS
      return ERR_OK;
#else
      return 1;
#endif
    }
  }
#endif

  /* copy IP addresses to aligned ip_addr_t */
  ip_addr_copy_from_ip4(ip_data.current_iphdr_dest, iphdr->dest);
  ip_addr_copy_from_ip4(ip_data.current_iphdr_src, iphdr->src);

#if !ZITI_TUNNELER_SDK_TAKE_ALL_PACKETS
  /* match packet against an interface, i.e. is this packet for us? */
  if (ip4_addr_ismulticast(ip4_current_dest_addr())) {
#if LWIP_IGMP
    if ((inp->flags & NETIF_FLAG_IGMP) && (igmp_lookfor_group(inp, ip4_current_dest_addr()))) {
      /* IGMP snooping switches need 0.0.0.0 to be allowed as source address (RFC 4541) */
      ip4_addr_t allsystems;
      IP4_ADDR(&allsystems, 224, 0, 0, 1);
      if (ip4_addr_cmp(ip4_current_dest_addr(), &allsystems) &&
          ip4_addr_isany(ip4_current_src_addr())) {
        check_ip_src = 0;
      }
      netif = inp;
    } else {
      netif = NULL;
    }
#else /* LWIP_IGMP */
    if ((netif_is_up(inp)) && (!ip4_addr_isany_val(*netif_ip4_addr(inp)))) {
      netif = inp;
    } else {
      netif = NULL;
    }
#endif /* LWIP_IGMP */
  } else {
    /* start trying with inp. if that's not acceptable, start walking the
       list of configured netifs. */
    if (ip4_input_accept(inp)) {
      netif = inp;
    } else {
      netif = NULL;
#if !LWIP_NETIF_LOOPBACK || LWIP_HAVE_LOOPIF
      /* Packets sent to the loopback address must not be accepted on an
       * interface that does not have the loopback address assigned to it,
       * unless a non-loopback interface is used for loopback traffic. */
      if (!ip4_addr_isloopback(ip4_current_dest_addr()))
#endif /* !LWIP_NETIF_LOOPBACK || LWIP_HAVE_LOOPIF */
      {
#if !LWIP_SINGLE_NETIF
        NETIF_FOREACH(netif) {
          if (netif == inp) {
            /* we checked that before already */
            continue;
          }
          if (ip4_input_accept(netif)) {
            break;
          }
        }
#endif /* !LWIP_SINGLE_NETIF */
      }
    }
  }

#if IP_ACCEPT_LINK_LAYER_ADDRESSING
  /* Pass DHCP messages regardless of destination address. DHCP traffic is addressed
   * using link layer addressing (such as Ethernet MAC) so we must not filter on IP.
   * According to RFC 1542 section 3.1.1, referred by RFC 2131).
   *
   * If you want to accept private broadcast communication while a netif is down,
   * define LWIP_IP_ACCEPT_UDP_PORT(dst_port), e.g.:
   *
   * #define LWIP_IP_ACCEPT_UDP_PORT(dst_port) ((dst_port) == PP_NTOHS(12345))
   */
  if (netif == NULL) {
    /* remote port is DHCP server? */
    if (IPH_PROTO(iphdr) == IP_PROTO_UDP) {
      const struct udp_hdr *udphdr = (const struct udp_hdr *)((const u8_t *)iphdr + iphdr_hlen);
      LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_TRACE, ("ip4_input: UDP packet to DHCP client port %"U16_F"\n",
                                              lwip_ntohs(udphdr->dest)));
      if (IP_ACCEPT_LINK_LAYER_ADDRESSED_PORT(udphdr->dest)) {
        LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_TRACE, ("ip4_input: DHCP packet accepted.\n"));
        netif = inp;
        check_ip_src = 0;
      }
    }
  }
#endif /* IP_ACCEPT_LINK_LAYER_ADDRESSING */

  /* broadcast or multicast packet source address? Compliant with RFC 1122: 3.2.1.3 */
#if LWIP_IGMP || IP_ACCEPT_LINK_LAYER_ADDRESSING
  if (check_ip_src
#if IP_ACCEPT_LINK_LAYER_ADDRESSING
      /* DHCP servers need 0.0.0.0 to be allowed as source address (RFC 1.1.2.2: 3.2.1.3/a) */
      && !ip4_addr_isany_val(*ip4_current_src_addr())
#endif /* IP_ACCEPT_LINK_LAYER_ADDRESSING */
     )
#endif /* LWIP_IGMP || IP_ACCEPT_LINK_LAYER_ADDRESSING */
  {
    if ((ip4_addr_isbroadcast(ip4_current_src_addr(), inp)) ||
        (ip4_addr_ismulticast(ip4_current_src_addr()))) {
      /* packet source is not valid */
      LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING, ("ip4_input: packet source is not valid.\n"));
      /* free (drop) packet pbufs */
      pbuf_free(p);
      IP_STATS_INC(ip.drop);
      MIB2_STATS_INC(mib2.ipinaddrerrors);
      MIB2_STATS_INC(mib2.ipindiscards);
      return ERR_OK;
    }
  }

  /* packet not for us? */
  if (netif == NULL) {
    /* packet not for us, route or discard */
    LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_TRACE, ("ip4_input: packet not for us.\n"));
#if IP_FORWARD
    /* non-broadcast packet? */
    if (!ip4_addr_isbroadcast(ip4_current_dest_addr(), inp)) {
      /* try to forward IP packet on (other) interfaces */
      ip4_forward(p, (struct ip_hdr *)p->payload, inp);
    } else
#endif /* IP_FORWARD */
    {
      IP_STATS_INC(ip.drop);
      MIB2_STATS_INC(mib2.ipinaddrerrors);
      MIB2_STATS_INC(mib2.ipindiscards);
    }
    pbuf_free(p);
    return ERR_OK;
  }
#else
  netif = inp;
#endif /* ZITI_TUNNELER_SDK_TAKE_ALL_PACKETS */

  /* packet consists of multiple fragments? */
  if ((IPH_OFFSET(iphdr) & PP_HTONS(IP_OFFMASK | IP_MF)) != 0) {
#if IP_REASSEMBLY /* packet fragment reassembly code present? */
    LWIP_DEBUGF(IP_DEBUG, ("IP packet is a fragment (id=0x%04"X16_F" tot_len=%"U16_F" len=%"U16_F" MF=%"U16_F" offset=%"U16_F"), calling ip4_reass()\n",
                           lwip_ntohs(IPH_ID(iphdr)), p->tot_len, lwip_ntohs(IPH_LEN(iphdr)), (u16_t)!!(IPH_OFFSET(iphdr) & PP_HTONS(IP_MF)), (u16_t)((lwip_ntohs(IPH_OFFSET(iphdr)) & IP_OFFMASK) * 8)));
    /* reassemble the packet*/
    p = ip4_reass(p);
    /* packet not fully reassembled yet? */
    if (p == NULL) {
#if !ZITI_TUNNELER_SDK_TAKE_ALL_PACKETS
      return ERR_OK;
#else
      return 1;
#endif
    }
    iphdr = (const struct ip_hdr *)p->payload;
#else /* IP_REASSEMBLY == 0, no packet fragment reassembly code present */
    pbuf_free(p);
    LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("IP packet dropped since it was fragmented (0x%"X16_F") (while IP_REASSEMBLY == 0).\n",
                lwip_ntohs(IPH_OFFSET(iphdr))));
    IP_STATS_INC(ip.opterr);
    IP_STATS_INC(ip.drop);
    /* unsupported protocol feature */
    MIB2_STATS_INC(mib2.ipinunknownprotos);
#if !ZITI_TUNNELER_SDK_TAKE_ALL_PACKETS
    return ERR_OK;
#else
    return 1;
#endif
#endif /* IP_REASSEMBLY */
  }

#if IP_OPTIONS_ALLOWED == 0 /* no support for IP options in the IP header? */

#if LWIP_IGMP
  /* there is an extra "router alert" option in IGMP messages which we allow for but do not police */
  if ((iphdr_hlen > IP_HLEN) &&  (IPH_PROTO(iphdr) != IP_PROTO_IGMP)) {
#else
  if (iphdr_hlen > IP_HLEN) {
#endif /* LWIP_IGMP */
    LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("IP packet dropped since there were IP options (while IP_OPTIONS_ALLOWED == 0).\n"));
    pbuf_free(p);
    IP_STATS_INC(ip.opterr);
    IP_STATS_INC(ip.drop);
    /* unsupported protocol feature */
    MIB2_STATS_INC(mib2.ipinunknownprotos);
#if !ZITI_TUNNELER_SDK_TAKE_ALL_PACKETS
    return ERR_OK;
#else
    return 1;
#endif
  }
#endif /* IP_OPTIONS_ALLOWED == 0 */

  /* send to upper layers */
  LWIP_DEBUGF(IP_DEBUG, ("ip4_input: \n"));
  ip4_debug_print(p);
  LWIP_DEBUGF(IP_DEBUG, ("ip4_input: p->len %"U16_F" p->tot_len %"U16_F"\n", p->len, p->tot_len));

  ip_data.current_netif = netif;
  ip_data.current_input_netif = inp;
  ip_data.current_ip4_header = iphdr;
  ip_data.current_ip_header_tot_len = IPH_HL_BYTES(iphdr);

#if LWIP_RAW
  /* raw input did not eat the packet? */
  raw_status = raw_input(p, inp);
  if (raw_status != RAW_INPUT_EATEN)
#endif /* LWIP_RAW */
  {
    pbuf_remove_header(p, iphdr_hlen); /* Move to payload, no check necessary. */

    switch (IPH_PROTO(iphdr)) {
#if LWIP_UDP
      case IP_PROTO_UDP:
#if LWIP_UDPLITE
      case IP_PROTO_UDPLITE:
#endif /* LWIP_UDPLITE */
        MIB2_STATS_INC(mib2.ipindelivers);
        udp_input(p, inp);
        break;
#endif /* LWIP_UDP */
#if LWIP_TCP
      case IP_PROTO_TCP:
        MIB2_STATS_INC(mib2.ipindelivers);
        tcp_input(p, inp);
        break;
#endif /* LWIP_TCP */
#if LWIP_ICMP
      case IP_PROTO_ICMP:
        MIB2_STATS_INC(mib2.ipindelivers);
        icmp_input(p, inp);
        break;
#endif /* LWIP_ICMP */
#if LWIP_IGMP
      case IP_PROTO_IGMP:
        igmp_input(p, inp, ip4_current_dest_addr());
        break;
#endif /* LWIP_IGMP */
      default:
#if LWIP_RAW
        if (raw_status == RAW_INPUT_DELIVERED) {
          MIB2_STATS_INC(mib2.ipindelivers);
        } else
#endif /* LWIP_RAW */
        {
#if LWIP_ICMP
          /* send ICMP destination protocol unreachable unless is was a broadcast */
          if (!ip4_addr_isbroadcast(ip4_current_dest_addr(), netif) &&
              !ip4_addr_ismulticast(ip4_current_dest_addr())) {
            pbuf_header_force(p, (s16_t)iphdr_hlen); /* Move to ip header, no check necessary. */
            icmp_dest_unreach(p, ICMP_DUR_PROTO);
          }
#endif /* LWIP_ICMP */

          LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("Unsupported transport protocol %"U16_F"\n", (u16_t)IPH_PROTO(iphdr)));

          IP_STATS_INC(ip.proterr);
          IP_STATS_INC(ip.drop);
          MIB2_STATS_INC(mib2.ipinunknownprotos);
        }
        pbuf_free(p);
        break;
    }
  }

  /* @todo: this is not really necessary... */
  ip_data.current_netif = NULL;
  ip_data.current_input_netif = NULL;
  ip_data.current_ip4_header = NULL;
  ip_data.current_ip_header_tot_len = 0;
  ip4_addr_set_any(ip4_current_src_addr());
  ip4_addr_set_any(ip4_current_dest_addr());

#if !ZITI_TUNNELER_SDK_TAKE_ALL_PACKETS
  return ERR_OK;
#else
  return 1;
#endif
}

#endif /* LWIP_IPV4 */
