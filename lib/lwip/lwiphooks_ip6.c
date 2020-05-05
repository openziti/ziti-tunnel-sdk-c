/*
 * copied from deps/lwip/src/core/ipv6/ip6.c
 *
 * This function is installed as an input hook for the ziti tunneler SDK.
 * the only change from the original lwip code is that we do not want to
 * match incoming packets to netifs based on IP address; we just take all
 * packets. Changes from the original lwip code are surrounded by
 * #if !ZITI_TUNNELER_SDK_TAKE_ALL_PACKETS.
 */

/*
 * Copyright (c) 2010 Inico Technologies Ltd.
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
 * Author: Ivan Delamer <delamer@inicotech.com>
 *
 *
 * Please coordinate changes and requests with Ivan Delamer
 * <delamer@inicotech.com>
 */

#include "lwip/opt.h"

#if LWIP_IPV6  /* don't build if not configured for use in lwipopts.h */

#include "lwip/def.h"
#include "lwip/mem.h"
#include "lwip/netif.h"
#include "lwip/ip.h"
#include "lwip/ip6.h"
#include "lwip/ip6_addr.h"
#include "lwip/ip6_frag.h"
#include "lwip/icmp6.h"
#include "lwip/priv/raw_priv.h"
#include "lwip/udp.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/dhcp6.h"
#include "lwip/nd6.h"
#include "lwip/mld6.h"
#include "lwip/debug.h"
#include "lwip/stats.h"

#ifdef LWIP_HOOK_FILENAME
#include LWIP_HOOK_FILENAME
#endif

int
ip6_input_hook(struct pbuf *p, struct netif *inp)
{
  struct ip6_hdr *ip6hdr;
  struct netif *netif;
  const u8_t *nexth;
  u16_t hlen, hlen_tot; /* the current header length */
#if 0 /*IP_ACCEPT_LINK_LAYER_ADDRESSING*/
  @todo
  int check_ip_src=1;
#endif /* IP_ACCEPT_LINK_LAYER_ADDRESSING */
#if LWIP_RAW
  raw_input_state_t raw_status;
#endif /* LWIP_RAW */

  LWIP_ASSERT_CORE_LOCKED();

  IP6_STATS_INC(ip6.recv);

  /* identify the IP header */
  ip6hdr = (struct ip6_hdr *)p->payload;
  if (IP6H_V(ip6hdr) != 6) {
    LWIP_DEBUGF(IP6_DEBUG | LWIP_DBG_LEVEL_WARNING, ("IPv6 packet dropped due to bad version number %"U32_F"\n",
        IP6H_V(ip6hdr)));
    pbuf_free(p);
    IP6_STATS_INC(ip6.err);
    IP6_STATS_INC(ip6.drop);
#if !ZITI_TUNNELER_SDK_TAKE_ALL_PACKETS
    return ERR_OK;
#else
    return 1;
#endif
  }

#if !ZITI_TUNNELER_SDK_TAKE_ALL_PACKETS  
#ifdef LWIP_HOOK_IP6_INPUT
  if (LWIP_HOOK_IP6_INPUT(p, inp)) {
    /* the packet has been eaten */
    return ERR_OK;
  }
#endif
#endif

  /* header length exceeds first pbuf length, or ip length exceeds total pbuf length? */
  if ((IP6_HLEN > p->len) || (IP6H_PLEN(ip6hdr) > (p->tot_len - IP6_HLEN))) {
    if (IP6_HLEN > p->len) {
      LWIP_DEBUGF(IP6_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
        ("IPv6 header (len %"U16_F") does not fit in first pbuf (len %"U16_F"), IP packet dropped.\n",
            (u16_t)IP6_HLEN, p->len));
    }
    if ((IP6H_PLEN(ip6hdr) + IP6_HLEN) > p->tot_len) {
      LWIP_DEBUGF(IP6_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
        ("IPv6 (plen %"U16_F") is longer than pbuf (len %"U16_F"), IP packet dropped.\n",
            (u16_t)(IP6H_PLEN(ip6hdr) + IP6_HLEN), p->tot_len));
    }
    /* free (drop) packet pbufs */
    pbuf_free(p);
    IP6_STATS_INC(ip6.lenerr);
    IP6_STATS_INC(ip6.drop);
#if !ZITI_TUNNELER_SDK_TAKE_ALL_PACKETS
    return ERR_OK;
#else
    return 1;
#endif
  }

  /* Trim pbuf. This should have been done at the netif layer,
   * but we'll do it anyway just to be sure that its done. */
  pbuf_realloc(p, (u16_t)(IP6_HLEN + IP6H_PLEN(ip6hdr)));

  /* copy IP addresses to aligned ip6_addr_t */
  ip_addr_copy_from_ip6_packed(ip_data.current_iphdr_dest, ip6hdr->dest);
  ip_addr_copy_from_ip6_packed(ip_data.current_iphdr_src, ip6hdr->src);

  /* Don't accept virtual IPv4 mapped IPv6 addresses.
   * Don't accept multicast source addresses. */
  if (ip6_addr_isipv4mappedipv6(ip_2_ip6(&ip_data.current_iphdr_dest)) ||
     ip6_addr_isipv4mappedipv6(ip_2_ip6(&ip_data.current_iphdr_src)) ||
     ip6_addr_ismulticast(ip_2_ip6(&ip_data.current_iphdr_src))) {
    /* free (drop) packet pbufs */
    pbuf_free(p);
    IP6_STATS_INC(ip6.err);
    IP6_STATS_INC(ip6.drop);
#if !ZITI_TUNNELER_SDK_TAKE_ALL_PACKETS
    return ERR_OK;
#else
    return 1;
#endif
  }

  /* Set the appropriate zone identifier on the addresses. */
  ip6_addr_assign_zone(ip_2_ip6(&ip_data.current_iphdr_dest), IP6_UNKNOWN, inp);
  ip6_addr_assign_zone(ip_2_ip6(&ip_data.current_iphdr_src), IP6_UNICAST, inp);

  /* current header pointer. */
  ip_data.current_ip6_header = ip6hdr;

  /* In netif, used in case we need to send ICMPv6 packets back. */
  ip_data.current_netif = inp;
  ip_data.current_input_netif = inp;

#if !ZITI_TUNNELER_SDK_TAKE_ALL_PACKETS
  /* match packet against an interface, i.e. is this packet for us? */
  if (ip6_addr_ismulticast(ip6_current_dest_addr())) {
    /* Always joined to multicast if-local and link-local all-nodes group. */
    if (ip6_addr_isallnodes_iflocal(ip6_current_dest_addr()) ||
        ip6_addr_isallnodes_linklocal(ip6_current_dest_addr())) {
      netif = inp;
    }
#if LWIP_IPV6_MLD
    else if (mld6_lookfor_group(inp, ip6_current_dest_addr())) {
      netif = inp;
    }
#else /* LWIP_IPV6_MLD */
    else if (ip6_addr_issolicitednode(ip6_current_dest_addr())) {
      u8_t i;
      /* Filter solicited node packets when MLD is not enabled
       * (for Neighbor discovery). */
      netif = NULL;
      for (i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
        if (ip6_addr_isvalid(netif_ip6_addr_state(inp, i)) &&
            ip6_addr_cmp_solicitednode(ip6_current_dest_addr(), netif_ip6_addr(inp, i))) {
          netif = inp;
          LWIP_DEBUGF(IP6_DEBUG, ("ip6_input: solicited node packet accepted on interface %c%c\n",
              netif->name[0], netif->name[1]));
          break;
        }
      }
    }
#endif /* LWIP_IPV6_MLD */
    else {
      netif = NULL;
    }
  } else {
    /* start trying with inp. if that's not acceptable, start walking the
       list of configured netifs. */
    if (ip6_input_accept(inp)) {
      netif = inp;
    } else {
      netif = NULL;
#if !IPV6_CUSTOM_SCOPES
      /* Shortcut: stop looking for other interfaces if either the source or
        * the destination has a scope constrained to this interface. Custom
        * scopes may break the 1:1 link/interface mapping, however. */
      if (ip6_addr_islinklocal(ip6_current_dest_addr()) ||
          ip6_addr_islinklocal(ip6_current_src_addr())) {
        goto netif_found;
      }
#endif /* !IPV6_CUSTOM_SCOPES */
#if !LWIP_NETIF_LOOPBACK || LWIP_HAVE_LOOPIF
      /* The loopback address is to be considered link-local. Packets to it
        * should be dropped on other interfaces, as per RFC 4291 Sec. 2.5.3.
        * Its implied scope means packets *from* the loopback address should
        * not be accepted on other interfaces, either. These requirements
        * cannot be implemented in the case that loopback traffic is sent
        * across a non-loopback interface, however. */
      if (ip6_addr_isloopback(ip6_current_dest_addr()) ||
          ip6_addr_isloopback(ip6_current_src_addr())) {
        goto netif_found;
      }
#endif /* !LWIP_NETIF_LOOPBACK || LWIP_HAVE_LOOPIF */
#if !LWIP_SINGLE_NETIF
      NETIF_FOREACH(netif) {
        if (netif == inp) {
          /* we checked that before already */
          continue;
        }
        if (ip6_input_accept(netif)) {
          break;
        }
      }
#endif /* !LWIP_SINGLE_NETIF */
    }
netif_found:
    LWIP_DEBUGF(IP6_DEBUG, ("ip6_input: packet accepted on interface %c%c\n",
        netif ? netif->name[0] : 'X', netif? netif->name[1] : 'X'));
  }

  /* "::" packet source address? (used in duplicate address detection) */
  if (ip6_addr_isany(ip6_current_src_addr()) &&
      (!ip6_addr_issolicitednode(ip6_current_dest_addr()))) {
    /* packet source is not valid */
    /* free (drop) packet pbufs */
    LWIP_DEBUGF(IP6_DEBUG, ("ip6_input: packet with src ANY_ADDRESS dropped\n"));
    pbuf_free(p);
    IP6_STATS_INC(ip6.drop);
    goto ip6_input_cleanup;
  }

  /* packet not for us? */
  if (netif == NULL) {
    /* packet not for us, route or discard */
    LWIP_DEBUGF(IP6_DEBUG | LWIP_DBG_TRACE, ("ip6_input: packet not for us.\n"));
#if LWIP_IPV6_FORWARD
    /* non-multicast packet? */
    if (!ip6_addr_ismulticast(ip6_current_dest_addr())) {
      /* try to forward IP packet on (other) interfaces */
      ip6_forward(p, ip6hdr, inp);
    }
#endif /* LWIP_IPV6_FORWARD */
    pbuf_free(p);
    goto ip6_input_cleanup;
  }
#else
  netif = inp;
#endif

  /* current netif pointer. */
  ip_data.current_netif = netif;

  /* Save next header type. */
  nexth = &IP6H_NEXTH(ip6hdr);

  /* Init header length. */
  hlen = hlen_tot = IP6_HLEN;

  /* Move to payload. */
  pbuf_remove_header(p, IP6_HLEN);

  /* Process known option extension headers, if present. */
  while (*nexth != IP6_NEXTH_NONE)
  {
    switch (*nexth) {
    case IP6_NEXTH_HOPBYHOP:
    {
      s32_t opt_offset;
      struct ip6_hbh_hdr *hbh_hdr;
      struct ip6_opt_hdr *opt_hdr;
      LWIP_DEBUGF(IP6_DEBUG, ("ip6_input: packet with Hop-by-Hop options header\n"));

      /* Get and check the header length, while staying in packet bounds. */
      hbh_hdr = (struct ip6_hbh_hdr *)p->payload;

      /* Get next header type. */
      nexth = &IP6_HBH_NEXTH(hbh_hdr);

      /* Get the header length. */
      hlen = (u16_t)(8 * (1 + hbh_hdr->_hlen));

      if ((p->len < 8) || (hlen > p->len)) {
        LWIP_DEBUGF(IP6_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
          ("IPv6 options header (hlen %"U16_F") does not fit in first pbuf (len %"U16_F"), IPv6 packet dropped.\n",
              hlen, p->len));
        /* free (drop) packet pbufs */
        pbuf_free(p);
        IP6_STATS_INC(ip6.lenerr);
        IP6_STATS_INC(ip6.drop);
        goto ip6_input_cleanup;
      }

      hlen_tot = (u16_t)(hlen_tot + hlen);

      /* The extended option header starts right after Hop-by-Hop header. */
      opt_offset = IP6_HBH_HLEN;
      while (opt_offset < hlen)
      {
        s32_t opt_dlen = 0;

        opt_hdr = (struct ip6_opt_hdr *)((u8_t *)hbh_hdr + opt_offset);

        switch (IP6_OPT_TYPE(opt_hdr)) {
        /* @todo: process IPV6 Hop-by-Hop option data */
        case IP6_PAD1_OPTION:
          /* PAD1 option doesn't have length and value field */
          opt_dlen = -1;
          break;
        case IP6_PADN_OPTION:
          opt_dlen = IP6_OPT_DLEN(opt_hdr);
          break;
        case IP6_ROUTER_ALERT_OPTION:
          opt_dlen = IP6_OPT_DLEN(opt_hdr);
          break;
        case IP6_JUMBO_OPTION:
          opt_dlen = IP6_OPT_DLEN(opt_hdr);
          break;
        default:
          /* Check 2 MSB of Hop-by-Hop header type. */
          switch (IP6_OPT_TYPE_ACTION(opt_hdr)) {
          case 1:
            /* Discard the packet. */
            LWIP_DEBUGF(IP6_DEBUG, ("ip6_input: packet with invalid Hop-by-Hop option type dropped.\n"));
            pbuf_free(p);
            IP6_STATS_INC(ip6.drop);
            goto ip6_input_cleanup;
          case 2:
            /* Send ICMP Parameter Problem */
            icmp6_param_problem(p, ICMP6_PP_OPTION, opt_hdr);
            LWIP_DEBUGF(IP6_DEBUG, ("ip6_input: packet with invalid Hop-by-Hop option type dropped.\n"));
            pbuf_free(p);
            IP6_STATS_INC(ip6.drop);
            goto ip6_input_cleanup;
          case 3:
            /* Send ICMP Parameter Problem if destination address is not a multicast address */
            if (!ip6_addr_ismulticast(ip6_current_dest_addr())) {
              icmp6_param_problem(p, ICMP6_PP_OPTION, opt_hdr);
            }
            LWIP_DEBUGF(IP6_DEBUG, ("ip6_input: packet with invalid Hop-by-Hop option type dropped.\n"));
            pbuf_free(p);
            IP6_STATS_INC(ip6.drop);
            goto ip6_input_cleanup;
          default:
            /* Skip over this option. */
            opt_dlen = IP6_OPT_DLEN(opt_hdr);
            break;
          }
          break;
        }

        /* Adjust the offset to move to the next extended option header */
        opt_offset = opt_offset + IP6_OPT_HLEN + opt_dlen;
      }
      pbuf_remove_header(p, hlen);
      break;
    }
    case IP6_NEXTH_DESTOPTS:
    {
      s32_t opt_offset;
      struct ip6_dest_hdr *dest_hdr;
      struct ip6_opt_hdr *opt_hdr;
      LWIP_DEBUGF(IP6_DEBUG, ("ip6_input: packet with Destination options header\n"));

      dest_hdr = (struct ip6_dest_hdr *)p->payload;

      /* Get next header type. */
      nexth = &IP6_DEST_NEXTH(dest_hdr);

      /* Get the header length. */
      hlen = 8 * (1 + dest_hdr->_hlen);
      if ((p->len < 8) || (hlen > p->len)) {
        LWIP_DEBUGF(IP6_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
          ("IPv6 options header (hlen %"U16_F") does not fit in first pbuf (len %"U16_F"), IPv6 packet dropped.\n",
              hlen, p->len));
        /* free (drop) packet pbufs */
        pbuf_free(p);
        IP6_STATS_INC(ip6.lenerr);
        IP6_STATS_INC(ip6.drop);
        goto ip6_input_cleanup;
      }

      hlen_tot = (u16_t)(hlen_tot + hlen);

      /* The extended option header starts right after Destination header. */
      opt_offset = IP6_DEST_HLEN;
      while (opt_offset < hlen)
      {
        s32_t opt_dlen = 0;

        opt_hdr = (struct ip6_opt_hdr *)((u8_t *)dest_hdr + opt_offset);

        switch (IP6_OPT_TYPE(opt_hdr))
        {
        /* @todo: process IPV6 Destination option data */
        case IP6_PAD1_OPTION:
          /* PAD1 option deosn't have length and value field */
          opt_dlen = -1;
          break;
        case IP6_PADN_OPTION:
          opt_dlen = IP6_OPT_DLEN(opt_hdr);
          break;
        case IP6_ROUTER_ALERT_OPTION:
          opt_dlen = IP6_OPT_DLEN(opt_hdr);
          break;
        case IP6_JUMBO_OPTION:
          opt_dlen = IP6_OPT_DLEN(opt_hdr);
          break;
        case IP6_HOME_ADDRESS_OPTION:
          opt_dlen = IP6_OPT_DLEN(opt_hdr);
          break;
        default:
          /* Check 2 MSB of Destination header type. */
          switch (IP6_OPT_TYPE_ACTION(opt_hdr))
          {
          case 1:
            /* Discard the packet. */
            LWIP_DEBUGF(IP6_DEBUG, ("ip6_input: packet with invalid destination option type dropped.\n"));
            pbuf_free(p);
            IP6_STATS_INC(ip6.drop);
            goto ip6_input_cleanup;
          case 2:
            /* Send ICMP Parameter Problem */
            icmp6_param_problem(p, ICMP6_PP_OPTION, opt_hdr);
            LWIP_DEBUGF(IP6_DEBUG, ("ip6_input: packet with invalid destination option type dropped.\n"));
            pbuf_free(p);
            IP6_STATS_INC(ip6.drop);
            goto ip6_input_cleanup;
          case 3:
            /* Send ICMP Parameter Problem if destination address is not a multicast address */
            if (!ip6_addr_ismulticast(ip6_current_dest_addr())) {
              icmp6_param_problem(p, ICMP6_PP_OPTION, opt_hdr);
            }
            LWIP_DEBUGF(IP6_DEBUG, ("ip6_input: packet with invalid destination option type dropped.\n"));
            pbuf_free(p);
            IP6_STATS_INC(ip6.drop);
            goto ip6_input_cleanup;
          default:
            /* Skip over this option. */
            opt_dlen = IP6_OPT_DLEN(opt_hdr);
            break;
          }
          break;
        }

        /* Adjust the offset to move to the next extended option header */
        opt_offset = opt_offset + IP6_OPT_HLEN + opt_dlen;
      }

      pbuf_remove_header(p, hlen);
      break;
    }
    case IP6_NEXTH_ROUTING:
    {
      struct ip6_rout_hdr *rout_hdr;
      LWIP_DEBUGF(IP6_DEBUG, ("ip6_input: packet with Routing header\n"));

      rout_hdr = (struct ip6_rout_hdr *)p->payload;

      /* Get next header type. */
      nexth = &IP6_ROUT_NEXTH(rout_hdr);

      /* Get the header length. */
      hlen = 8 * (1 + rout_hdr->_hlen);

      if ((p->len < 8) || (hlen > p->len)) {
        LWIP_DEBUGF(IP6_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
          ("IPv6 options header (hlen %"U16_F") does not fit in first pbuf (len %"U16_F"), IPv6 packet dropped.\n",
              hlen, p->len));
        /* free (drop) packet pbufs */
        pbuf_free(p);
        IP6_STATS_INC(ip6.lenerr);
        IP6_STATS_INC(ip6.drop);
        goto ip6_input_cleanup;
      }

      /* Skip over this header. */
      hlen_tot = (u16_t)(hlen_tot + hlen);

      /* if segment left value is 0 in routing header, ignore the option */
      if (IP6_ROUT_SEG_LEFT(rout_hdr)) {
        /* The length field of routing option header must be even */
        if (rout_hdr->_hlen & 0x1) {
          /* Discard and send parameter field error */
          icmp6_param_problem(p, ICMP6_PP_FIELD, &rout_hdr->_hlen);
          LWIP_DEBUGF(IP6_DEBUG, ("ip6_input: packet with invalid routing type dropped\n"));
          pbuf_free(p);
          IP6_STATS_INC(ip6.drop);
          goto ip6_input_cleanup;
        }

        switch (IP6_ROUT_TYPE(rout_hdr))
        {
        /* TODO: process routing by the type */
        case IP6_ROUT_TYPE2:
          break;
        case IP6_ROUT_RPL:
          break;
        default:
          /* Discard unrecognized routing type and send parameter field error */
          icmp6_param_problem(p, ICMP6_PP_FIELD, &IP6_ROUT_TYPE(rout_hdr));
          LWIP_DEBUGF(IP6_DEBUG, ("ip6_input: packet with invalid routing type dropped\n"));
          pbuf_free(p);
          IP6_STATS_INC(ip6.drop);
          goto ip6_input_cleanup;
        }
      }

      pbuf_remove_header(p, hlen);
      break;
    }
    case IP6_NEXTH_FRAGMENT:
    {
      struct ip6_frag_hdr *frag_hdr;
      LWIP_DEBUGF(IP6_DEBUG, ("ip6_input: packet with Fragment header\n"));

      frag_hdr = (struct ip6_frag_hdr *)p->payload;

      /* Get next header type. */
      nexth = &IP6_FRAG_NEXTH(frag_hdr);

      /* Fragment Header length. */
      hlen = 8;

      /* Make sure this header fits in current pbuf. */
      if (hlen > p->len) {
        LWIP_DEBUGF(IP6_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
          ("IPv6 options header (hlen %"U16_F") does not fit in first pbuf (len %"U16_F"), IPv6 packet dropped.\n",
              hlen, p->len));
        /* free (drop) packet pbufs */
        pbuf_free(p);
        IP6_FRAG_STATS_INC(ip6_frag.lenerr);
        IP6_FRAG_STATS_INC(ip6_frag.drop);
        goto ip6_input_cleanup;
      }

      hlen_tot = (u16_t)(hlen_tot + hlen);

      /* check payload length is multiple of 8 octets when mbit is set */
      if (IP6_FRAG_MBIT(frag_hdr) && (IP6H_PLEN(ip6hdr) & 0x7)) {
        /* ipv6 payload length is not multiple of 8 octets */
        icmp6_param_problem(p, ICMP6_PP_FIELD, LWIP_PACKED_CAST(const void *, &ip6hdr->_plen));
        LWIP_DEBUGF(IP6_DEBUG, ("ip6_input: packet with invalid payload length dropped\n"));
        pbuf_free(p);
        IP6_STATS_INC(ip6.drop);
        goto ip6_input_cleanup;
      }

      /* Offset == 0 and more_fragments == 0? */
      if ((frag_hdr->_fragment_offset &
           PP_HTONS(IP6_FRAG_OFFSET_MASK | IP6_FRAG_MORE_FLAG)) == 0) {
        /* This is a 1-fragment packet. Skip this header and continue. */
        pbuf_remove_header(p, hlen);
      } else {
#if LWIP_IPV6_REASS
        /* reassemble the packet */
        ip_data.current_ip_header_tot_len = hlen_tot;
        p = ip6_reass(p);
        /* packet not fully reassembled yet? */
        if (p == NULL) {
          goto ip6_input_cleanup;
        }

        /* Returned p point to IPv6 header.
         * Update all our variables and pointers and continue. */
        ip6hdr = (struct ip6_hdr *)p->payload;
        nexth = &IP6H_NEXTH(ip6hdr);
        hlen = hlen_tot = IP6_HLEN;
        pbuf_remove_header(p, IP6_HLEN);

#else /* LWIP_IPV6_REASS */
        /* free (drop) packet pbufs */
        LWIP_DEBUGF(IP6_DEBUG, ("ip6_input: packet with Fragment header dropped (with LWIP_IPV6_REASS==0)\n"));
        pbuf_free(p);
        IP6_STATS_INC(ip6.opterr);
        IP6_STATS_INC(ip6.drop);
        goto ip6_input_cleanup;
#endif /* LWIP_IPV6_REASS */
      }
      break;
    }
    default:
      goto options_done;
    }

    if (*nexth == IP6_NEXTH_HOPBYHOP) {
      /* Hop-by-Hop header comes only as a first option */
      icmp6_param_problem(p, ICMP6_PP_HEADER, nexth);
      LWIP_DEBUGF(IP6_DEBUG, ("ip6_input: packet with Hop-by-Hop options header dropped (only valid as a first option)\n"));
      pbuf_free(p);
      IP6_STATS_INC(ip6.drop);
      goto ip6_input_cleanup;
    }
  }

options_done:

  /* send to upper layers */
  LWIP_DEBUGF(IP6_DEBUG, ("ip6_input: \n"));
  ip6_debug_print(p);
  LWIP_DEBUGF(IP6_DEBUG, ("ip6_input: p->len %"U16_F" p->tot_len %"U16_F"\n", p->len, p->tot_len));

  ip_data.current_ip_header_tot_len = hlen_tot;
  
#if LWIP_RAW
  /* p points to IPv6 header again for raw_input. */
  pbuf_add_header_force(p, hlen_tot);
  /* raw input did not eat the packet? */
  raw_status = raw_input(p, inp);
  if (raw_status != RAW_INPUT_EATEN)
  {
    /* Point to payload. */
    pbuf_remove_header(p, hlen_tot);
#else /* LWIP_RAW */
  {
#endif /* LWIP_RAW */
    switch (*nexth) {
    case IP6_NEXTH_NONE:
      pbuf_free(p);
      break;
#if LWIP_UDP
    case IP6_NEXTH_UDP:
#if LWIP_UDPLITE
    case IP6_NEXTH_UDPLITE:
#endif /* LWIP_UDPLITE */
      udp_input(p, inp);
      break;
#endif /* LWIP_UDP */
#if LWIP_TCP
    case IP6_NEXTH_TCP:
      tcp_input(p, inp);
      break;
#endif /* LWIP_TCP */
#if LWIP_ICMP6
    case IP6_NEXTH_ICMP6:
      icmp6_input(p, inp);
      break;
#endif /* LWIP_ICMP */
    default:
#if LWIP_RAW
        if (raw_status == RAW_INPUT_DELIVERED) {
          /* @todo: ipv6 mib in-delivers? */
        } else
#endif /* LWIP_RAW */
        {
#if LWIP_ICMP6
        /* p points to IPv6 header again for raw_input. */
        pbuf_add_header_force(p, hlen_tot);
        /* send ICMP parameter problem unless it was a multicast or ICMPv6 */
        if ((!ip6_addr_ismulticast(ip6_current_dest_addr())) &&
            (IP6H_NEXTH(ip6hdr) != IP6_NEXTH_ICMP6)) {
          icmp6_param_problem(p, ICMP6_PP_HEADER, nexth);
        }
#endif /* LWIP_ICMP */
        LWIP_DEBUGF(IP6_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("ip6_input: Unsupported transport protocol %"U16_F"\n", (u16_t)IP6H_NEXTH(ip6hdr)));
        IP6_STATS_INC(ip6.proterr);
        IP6_STATS_INC(ip6.drop);
      }
      pbuf_free(p);
      break;
    }
  }

ip6_input_cleanup:
  ip_data.current_netif = NULL;
  ip_data.current_input_netif = NULL;
  ip_data.current_ip6_header = NULL;
  ip_data.current_ip_header_tot_len = 0;
  ip6_addr_set_zero(ip6_current_src_addr());
  ip6_addr_set_zero(ip6_current_dest_addr());

#if !ZITI_TUNNELER_SDK_TAKE_ALL_PACKETS
  return ERR_OK;
#else
  return 1;
#endif
}

#endif /* LWIP_IPV6 */
