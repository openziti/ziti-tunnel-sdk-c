#include "lwip_cloned_fns.h"
#include "lwip/priv/tcp_priv.h"
#if CHECKSUM_CHECK_TCP
#include "lwip/inet_chksum.h"
#endif

/* These variables are global to all functions involved in the input
   processing of TCP segments. They are set by the tcp_input()
   function. */
static struct tcp_hdr *tcphdr;
static u16_t tcphdr_optlen;
static u16_t tcphdr_opt1len;
static u8_t *tcphdr_opt2;
static u16_t tcp_optidx;
static u32_t seqno, ackno;
static tcpwnd_size_t recv_acked;
static u16_t tcplen;
static u8_t flags;

/**
 * The initial input processing of TCP. It verifies the TCP header, demultiplexes
 * the segment between the PCBs and passes it on to tcp_process(), which implements
 * the TCP finite state machine. This function is called by the IP layer (in
 * ip_input()).
 *
 * @param p received TCP segment to process (p->payload pointing to the TCP header)
 */
void
tunneler_tcp_input(struct pbuf *p)
{
  u8_t hdrlen_bytes;

  LWIP_ASSERT_CORE_LOCKED();
  LWIP_ASSERT("tcp_input: invalid pbuf", p != NULL);

  PERF_START;

  TCP_STATS_INC(tcp.recv);
  MIB2_STATS_INC(mib2.tcpinsegs);

  tcphdr = (struct tcp_hdr *)p->payload;

#if TCP_INPUT_DEBUG
  tcp_debug_print(tcphdr);
#endif

  /* Check that TCP header fits in payload */
  if (p->len < TCP_HLEN) {
    /* drop short packets */
    LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: short packet (%"U16_F" bytes) discarded\n", p->tot_len));
    TCP_STATS_INC(tcp.lenerr);
    goto dropped;
  }

  /* Don't even process incoming broadcasts/multicasts. */
  if (ip_addr_isbroadcast(ip_current_dest_addr(), ip_current_netif()) ||
      ip_addr_ismulticast(ip_current_dest_addr())) {
    TCP_STATS_INC(tcp.proterr);
    goto dropped;
  }

#if CHECKSUM_CHECK_TCP
  IF__NETIF_CHECKSUM_ENABLED(inp, NETIF_CHECKSUM_CHECK_TCP) {
    /* Verify TCP checksum. */
    u16_t chksum = ip_chksum_pseudo(p, IP_PROTO_TCP, p->tot_len,
                                    ip_current_src_addr(), ip_current_dest_addr());
    if (chksum != 0) {
      LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: packet discarded due to failing checksum 0x%04"X16_F"\n",
                                    chksum));
      tcp_debug_print(tcphdr);
      TCP_STATS_INC(tcp.chkerr);
      goto dropped;
    }
  }
#endif /* CHECKSUM_CHECK_TCP */

  /* sanity-check header length */
  hdrlen_bytes = TCPH_HDRLEN_BYTES(tcphdr);
  if ((hdrlen_bytes < TCP_HLEN) || (hdrlen_bytes > p->tot_len)) {
    LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: invalid header length (%"U16_F")\n", (u16_t)hdrlen_bytes));
    TCP_STATS_INC(tcp.lenerr);
    goto dropped;
  }

  /* Move the payload pointer in the pbuf so that it points to the
     TCP data instead of the TCP header. */
  tcphdr_optlen = (u16_t)(hdrlen_bytes - TCP_HLEN);
  tcphdr_opt2 = NULL;
  if (p->len >= hdrlen_bytes) {
    /* all options are in the first pbuf */
    tcphdr_opt1len = tcphdr_optlen;
    pbuf_remove_header(p, hdrlen_bytes); /* cannot fail */
  } else {
    u16_t opt2len;
    /* TCP header fits into first pbuf, options don't - data is in the next pbuf */
    /* there must be a next pbuf, due to hdrlen_bytes sanity check above */
    LWIP_ASSERT("p->next != NULL", p->next != NULL);

    /* advance over the TCP header (cannot fail) */
    pbuf_remove_header(p, TCP_HLEN);

    /* determine how long the first and second parts of the options are */
    tcphdr_opt1len = p->len;
    opt2len = (u16_t)(tcphdr_optlen - tcphdr_opt1len);

    /* options continue in the next pbuf: set p to zero length and hide the
        options in the next pbuf (adjusting p->tot_len) */
    pbuf_remove_header(p, tcphdr_opt1len);

    /* check that the options fit in the second pbuf */
    if (opt2len > p->next->len) {
      /* drop short packets */
      LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: options overflow second pbuf (%"U16_F" bytes)\n", p->next->len));
      TCP_STATS_INC(tcp.lenerr);
      goto dropped;
    }

    /* remember the pointer to the second part of the options */
    tcphdr_opt2 = (u8_t *)p->next->payload;

    /* advance p->next to point after the options, and manually
        adjust p->tot_len to keep it consistent with the changed p->next */
    pbuf_remove_header(p->next, opt2len);
    p->tot_len = (u16_t)(p->tot_len - opt2len);

    LWIP_ASSERT("p->len == 0", p->len == 0);
    LWIP_ASSERT("p->tot_len == p->next->tot_len", p->tot_len == p->next->tot_len);
  }

  /* Convert fields in TCP header to host byte order. */
  tcphdr->src = lwip_ntohs(tcphdr->src);
  tcphdr->dest = lwip_ntohs(tcphdr->dest);
  seqno = tcphdr->seqno = lwip_ntohl(tcphdr->seqno);
  ackno = tcphdr->ackno = lwip_ntohl(tcphdr->ackno);
  tcphdr->wnd = lwip_ntohs(tcphdr->wnd);

  flags = TCPH_FLAGS(tcphdr);
  tcplen = p->tot_len;
  if (flags & (TCP_FIN | TCP_SYN)) {
    tcplen++;
    if (tcplen < p->tot_len) {
      /* u16_t overflow, cannot handle this */
      LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: length u16_t overflow, cannot handle this\n"));
      TCP_STATS_INC(tcp.lenerr);
      goto dropped;
    }
  }

#if TCP_INPUT_DEBUG
  LWIP_DEBUGF(TCP_INPUT_DEBUG, ("+-+-+-+-+-+-+-+-+-+-+-+-+-+- tcp_input: flags "));
  tcp_debug_print_flags(TCPH_FLAGS(tcphdr));
  LWIP_DEBUGF(TCP_INPUT_DEBUG, ("-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"));
#endif /* TCP_INPUT_DEBUG */

  LWIP_ASSERT("tcp_input: tcp_pcbs_sane()", tcp_pcbs_sane());
  PERF_STOP("tcp_input");
  return;
dropped:
  TCP_STATS_INC(tcp.drop);
  MIB2_STATS_INC(mib2.tcpinerrs);
  //pbuf_free(p);
}

static u8_t
tcp_get_next_optbyte(void)
{
  u16_t optidx = tcp_optidx++;
  if ((tcphdr_opt2 == NULL) || (optidx < tcphdr_opt1len)) {
    u8_t *opts = (u8_t *)tcphdr + TCP_HLEN;
    return opts[optidx];
  } else {
    u8_t idx = (u8_t)(optidx - tcphdr_opt1len);
    return tcphdr_opt2[idx];
  }
}

/**
 * Parses the options contained in the incoming segment.
 *
 * Called from tcp_listen_input() and tcp_process().
 * Currently, only the MSS option is supported!
 *
 * @param pcb the tcp_pcb for which a segment arrived
 */
void
tunneler_tcp_parseopt(struct tcp_pcb *pcb)
{
  u8_t data;
  u16_t mss;
#if LWIP_TCP_TIMESTAMPS
  u32_t tsval;
#endif

  LWIP_ASSERT("tcp_parseopt: invalid pcb", pcb != NULL);

  /* Parse the TCP MSS option, if present. */
  if (tcphdr_optlen != 0) {
    for (tcp_optidx = 0; tcp_optidx < tcphdr_optlen; ) {
      u8_t opt = tcp_get_next_optbyte();
      switch (opt) {
        case LWIP_TCP_OPT_EOL:
          /* End of options. */
          LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_parseopt: EOL\n"));
          return;
        case LWIP_TCP_OPT_NOP:
          /* NOP option. */
          LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_parseopt: NOP\n"));
          break;
        case LWIP_TCP_OPT_MSS:
          LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_parseopt: MSS\n"));
          if (tcp_get_next_optbyte() != LWIP_TCP_OPT_LEN_MSS || (tcp_optidx - 2 + LWIP_TCP_OPT_LEN_MSS) > tcphdr_optlen) {
            /* Bad length */
            LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_parseopt: bad length\n"));
            return;
          }
          /* An MSS option with the right option length. */
          mss = (u16_t)(tcp_get_next_optbyte() << 8);
          mss |= tcp_get_next_optbyte();
          /* Limit the mss to the configured TCP_MSS and prevent division by zero */
          pcb->mss = ((mss > TCP_MSS) || (mss == 0)) ? TCP_MSS : mss;
          break;
#if LWIP_WND_SCALE
        case LWIP_TCP_OPT_WS:
          LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_parseopt: WND_SCALE\n"));
          if (tcp_get_next_optbyte() != LWIP_TCP_OPT_LEN_WS || (tcp_optidx - 2 + LWIP_TCP_OPT_LEN_WS) > tcphdr_optlen) {
            /* Bad length */
            LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_parseopt: bad length\n"));
            return;
          }
          /* An WND_SCALE option with the right option length. */
          data = tcp_get_next_optbyte();
          /* If syn was received with wnd scale option,
             activate wnd scale opt, but only if this is not a retransmission */
          if ((flags & TCP_SYN) && !(pcb->flags & TF_WND_SCALE)) {
            pcb->snd_scale = data;
            if (pcb->snd_scale > 14U) {
              pcb->snd_scale = 14U;
            }
            pcb->rcv_scale = TCP_RCV_SCALE;
            tcp_set_flags(pcb, TF_WND_SCALE);
            /* window scaling is enabled, we can use the full receive window */
            LWIP_ASSERT("window not at default value", pcb->rcv_wnd == TCPWND_MIN16(TCP_WND));
            LWIP_ASSERT("window not at default value", pcb->rcv_ann_wnd == TCPWND_MIN16(TCP_WND));
            pcb->rcv_wnd = pcb->rcv_ann_wnd = TCP_WND;
          }
          break;
#endif /* LWIP_WND_SCALE */
#if LWIP_TCP_TIMESTAMPS
        case LWIP_TCP_OPT_TS:
          LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_parseopt: TS\n"));
          if (tcp_get_next_optbyte() != LWIP_TCP_OPT_LEN_TS || (tcp_optidx - 2 + LWIP_TCP_OPT_LEN_TS) > tcphdr_optlen) {
            /* Bad length */
            LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_parseopt: bad length\n"));
            return;
          }
          /* TCP timestamp option with valid length */
          tsval = tcp_get_next_optbyte();
          tsval |= (tcp_get_next_optbyte() << 8);
          tsval |= (tcp_get_next_optbyte() << 16);
          tsval |= (tcp_get_next_optbyte() << 24);
          if (flags & TCP_SYN) {
            pcb->ts_recent = lwip_ntohl(tsval);
            /* Enable sending timestamps in every segment now that we know
               the remote host supports it. */
            tcp_set_flags(pcb, TF_TIMESTAMP);
          } else if (TCP_SEQ_BETWEEN(pcb->ts_lastacksent, seqno, seqno + tcplen)) {
            pcb->ts_recent = lwip_ntohl(tsval);
          }
          /* Advance to next option (6 bytes already read) */
          tcp_optidx += LWIP_TCP_OPT_LEN_TS - 6;
          break;
#endif /* LWIP_TCP_TIMESTAMPS */
#if LWIP_TCP_SACK_OUT
        case LWIP_TCP_OPT_SACK_PERM:
          LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_parseopt: SACK_PERM\n"));
          if (tcp_get_next_optbyte() != LWIP_TCP_OPT_LEN_SACK_PERM || (tcp_optidx - 2 + LWIP_TCP_OPT_LEN_SACK_PERM) > tcphdr_optlen) {
            /* Bad length */
            LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_parseopt: bad length\n"));
            return;
          }
          /* TCP SACK_PERM option with valid length */
          if (flags & TCP_SYN) {
            /* We only set it if we receive it in a SYN (or SYN+ACK) packet */
            tcp_set_flags(pcb, TF_SACK);
          }
          break;
#endif /* LWIP_TCP_SACK_OUT */
        default:
          LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_parseopt: other\n"));
          data = tcp_get_next_optbyte();
          if (data < 2) {
            LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_parseopt: bad length\n"));
            /* If the length field is zero, the options are malformed
               and we don't process them further. */
            return;
          }
          /* All other options have a length field, so that we easily
             can skip past them. */
          tcp_optidx += data - 2;
      }
    }
  }
}