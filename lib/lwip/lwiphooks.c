#include "lwiphooks.h"
#include "lwip/ip.h"
#include "lwip/inet_chksum.h"
#include "lwip/ip4_frag.h"
#include "lwip/priv/raw_priv.h"
#include "lwip/udp.h"
#include "lwip/priv/tcp_priv.h"

/** copied from lwip/src/ip4.c. modified to accept all packets (no IP matching) */
int ip4_input_hook(struct pbuf *p, struct netif *inp)
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
        return ERR_OK;
    }

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
        return 1;
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
            return 1;
        }
    }
#endif

    /* copy IP addresses to aligned ip_addr_t */
    ip_addr_copy_from_ip4(ip_data.current_iphdr_dest, iphdr->dest);
    ip_addr_copy_from_ip4(ip_data.current_iphdr_src, iphdr->src);

    netif = inp;

    /* packet consists of multiple fragments? */
    if ((IPH_OFFSET(iphdr) & PP_HTONS(IP_OFFMASK | IP_MF)) != 0) {
#if IP_REASSEMBLY /* packet fragment reassembly code present? */
        LWIP_DEBUGF(IP_DEBUG, ("IP packet is a fragment (id=0x%04"X16_F" tot_len=%"U16_F" len=%"U16_F" MF=%"U16_F" offset=%"U16_F"), calling ip4_reass()\n",
                lwip_ntohs(IPH_ID(iphdr)), p->tot_len, lwip_ntohs(IPH_LEN(iphdr)), (u16_t)!!(IPH_OFFSET(iphdr) & PP_HTONS(IP_MF)), (u16_t)((lwip_ntohs(IPH_OFFSET(iphdr)) & IP_OFFMASK) * 8)));
        /* reassemble the packet*/
        p = ip4_reass(p);
        /* packet not fully reassembled yet? */
        if (p == NULL) {
            return 1;
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
    return 1;
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
    return 1;
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

    return 1;
}