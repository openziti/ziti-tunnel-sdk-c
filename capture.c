/*
 * capture.c - Read raw Ethernet frames from an OpenVPN TAP-Windows adapter
 *             using direct Win32 device I/O. No Npcap, no libpcap.
 *
 * Also acts as a minimal DHCP server on the TAP so Windows drops the
 * 169.254 auto-config address and takes the IP we assign instead.
 *
 * Usage: capture.exe [client-ip] [frame-count]
 *   client-ip   : IP to assign via DHCP  (default 100.100.100.100)
 *   frame-count : stop after N frames    (default unlimited)
 *
 * The server/gateway IP is derived automatically as x.x.x.1 of the
 * same /24 as the client IP.
 *
 * Build:
 *   cmake -B build && cmake --build build
 *
 * Run as Administrator.
 */

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <winioctl.h>
#include <ws2tcpip.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifndef _countof
#define _countof(a) (sizeof(a) / sizeof((a)[0]))
#endif

/* -------------------------------------------------------------------------
 * TAP-Windows IOCTLs
 * ---------------------------------------------------------------------- */
#define TAP_WIN_CONTROL_CODE(req, method) \
    CTL_CODE(FILE_DEVICE_UNKNOWN, (req), (method), FILE_ANY_ACCESS)

#define TAP_WIN_IOCTL_GET_VERSION       TAP_WIN_CONTROL_CODE(2, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_SET_MEDIA_STATUS  TAP_WIN_CONTROL_CODE(6, METHOD_BUFFERED)

#define ADAPTER_REG_KEY \
    "SYSTEM\\CurrentControlSet\\Control\\Class\\" \
    "{4D36E972-E325-11CE-BFC1-08002BE10318}"

#define MAX_FRAME_LEN        65536u
#define MIN_IPV4_HDR_LEN     20u
#define MIN_UDP_HDR_LEN       8u
#define DHCP_FIXED_PART_LEN 240u /* BOOTP header (236) + magic cookie (4) */

/* -------------------------------------------------------------------------
 * DHCP / IP configuration
 * ---------------------------------------------------------------------- */
static uint8_t CLIENT_IP[4] = { 100, 100, 100, 100 };
static uint8_t SERVER_IP[4] = { 100, 100, 100,   1 };
static const uint8_t SUBNET[4]     = { 255, 255, 255,   0 };
static const uint8_t BROADCAST[4]  = { 255, 255, 255, 255 };
static const uint8_t DNS_IP[4]     = {   8,   8,   8,   8 };
static const uint8_t SERVER_MAC[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
#define DHCP_LEASE_SECS 86400u

/* -------------------------------------------------------------------------
 * Wire-format structs
 * ---------------------------------------------------------------------- */
#pragma pack(push, 1)

typedef struct {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t ethertype;
} eth_hdr_t;

typedef struct {
    uint8_t  ver_ihl, dscp_ecn;
    uint16_t total_len, id, flags_frag;
    uint8_t  ttl, proto;
    uint16_t checksum;
    uint8_t  src[4], dst[4];
} ipv4_hdr_t;

typedef struct {
    uint8_t  ver_tc_hi, tc_lo_fl_hi;
    uint16_t fl_lo, payload_len;
    uint8_t  next_hdr, hop_limit;
    uint8_t  src[16], dst[16];
} ipv6_hdr_t;

typedef struct {
    uint16_t hw_type, proto_type;
    uint8_t  hw_len, proto_len;
    uint16_t operation;
    uint8_t  sender_mac[6], sender_ip[4];
    uint8_t  target_mac[6], target_ip[4];
} arp_hdr_t;

typedef struct {
    uint16_t src_port, dst_port;
    uint32_t seq, ack;
    uint8_t  data_off, flags;
    uint16_t window, checksum, urgent;
} tcp_hdr_t;

typedef struct {
    uint16_t src_port, dst_port, length, checksum;
} udp_hdr_t;

typedef struct {
    uint8_t  type, code;
    uint16_t checksum;
} icmp_hdr_t;

typedef struct {
    uint8_t  op, htype, hlen, hops;
    uint32_t xid;
    uint16_t secs, flags;
    uint8_t  ciaddr[4], yiaddr[4], siaddr[4], giaddr[4];
    uint8_t  chaddr[16];
    uint8_t  sname[64];
    uint8_t  file[128];
    /* options follow */
} dhcp_hdr_t;

#pragma pack(pop)

/* -------------------------------------------------------------------------
 * Globals
 * ---------------------------------------------------------------------- */
static HANDLE        g_tap        = INVALID_HANDLE_VALUE;
static HANDLE        g_write_event = NULL;
static volatile LONG g_stop       = 0;
static int           g_count      = 0;
static int           g_hex_dump   = 0;

/* -------------------------------------------------------------------------
 * Hex dump
 * ---------------------------------------------------------------------- */
static void hex_dump(const uint8_t *data, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        if (i % 16 == 0)
            printf("        %04zx  ", i);
        printf("%02x ", data[i]);
        if (i % 16 == 15 || i == len - 1) {
            size_t col = i % 16;
            if (col < 15) {
                size_t pad;
                for (pad = col + 1; pad < 16; pad++) printf("   ");
            }
            size_t row_start = i - (i % 16);
            size_t row_count = i - row_start + 1;
            printf(" |");
            for (size_t j = row_start; j <= i; j++)
                printf("%c", (data[j] >= 0x20 && data[j] < 0x7f) ? data[j] : '.');
            for (size_t p = row_count; p < 16; p++) printf(" ");
            printf("|\n");
        }
    }
    printf("\n");
}

/* -------------------------------------------------------------------------
 * Endian / bounds helpers
 * ---------------------------------------------------------------------- */
static uint16_t read_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static void write_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)((v >> 8) & 0xff);
    p[1] = (uint8_t)(v & 0xff);
}

static void write_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)((v >> 24) & 0xff);
    p[1] = (uint8_t)((v >> 16) & 0xff);
    p[2] = (uint8_t)((v >>  8) & 0xff);
    p[3] = (uint8_t)(v & 0xff);
}

static int range_ok(size_t total, size_t off, size_t need)
{
    return off <= total && need <= total - off;
}

/* -------------------------------------------------------------------------
 * Formatting helpers
 * ---------------------------------------------------------------------- */
static void print_mac(const uint8_t *a)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x", a[0], a[1], a[2], a[3], a[4], a[5]);
}

static void print_ipv4(const uint8_t *a)
{
    printf("%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
}

static void fmt_mac(char *buf, size_t buflen, const uint8_t *a)
{
    if (buflen == 0) return;
    _snprintf_s(buf, buflen, _TRUNCATE,
                "%02x:%02x:%02x:%02x:%02x:%02x",
                a[0], a[1], a[2], a[3], a[4], a[5]);
}

static void fmt_ipv4(char *buf, size_t buflen, const uint8_t *a)
{
    if (buflen == 0) return;
    _snprintf_s(buf, buflen, _TRUNCATE,
                "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
}

static void fmt_ipv6(char *buf, size_t buflen, const uint8_t *a)
{
    if (buflen == 0) return;
    _snprintf_s(buf, buflen, _TRUNCATE,
                "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
                "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7],
                a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15]);
}

static const char *tcp_flags_str(uint8_t f)
{
    static char b[32];
    b[0] = '\0';
    if (f & 0x02) strcat_s(b, sizeof(b), "SYN ");
    if (f & 0x10) strcat_s(b, sizeof(b), "ACK ");
    if (f & 0x01) strcat_s(b, sizeof(b), "FIN ");
    if (f & 0x04) strcat_s(b, sizeof(b), "RST ");
    if (f & 0x08) strcat_s(b, sizeof(b), "PSH ");
    if (!b[0])    strcat_s(b, sizeof(b), "NONE");
    return b;
}

/* -------------------------------------------------------------------------
 * Checksums
 * ---------------------------------------------------------------------- */
static uint16_t checksum16(const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    uint32_t sum = 0;

    while (len >= 2) {
        sum += ((uint32_t)p[0] << 8) | (uint32_t)p[1];
        p += 2;
        len -= 2;
    }
    if (len) {
        sum += ((uint32_t)p[0] << 8);
    }
    while (sum >> 16) {
        sum = (sum & 0xffffu) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

static uint16_t transport_checksum_ipv4(const uint8_t src[4],
                                        const uint8_t dst[4],
                                        uint8_t proto,
                                        const void *seg_data,
                                        size_t seg_len)
{
    const uint8_t *p = (const uint8_t *)seg_data;
    uint32_t sum = 0;
    size_t len = seg_len;

    sum += ((uint32_t)src[0] << 8) | src[1];
    sum += ((uint32_t)src[2] << 8) | src[3];
    sum += ((uint32_t)dst[0] << 8) | dst[1];
    sum += ((uint32_t)dst[2] << 8) | dst[3];
    sum += (uint32_t)proto;
    sum += (uint32_t)seg_len;

    while (len >= 2) {
        sum += ((uint32_t)p[0] << 8) | p[1];
        p += 2;
        len -= 2;
    }
    if (len) {
        sum += ((uint32_t)p[0] << 8);
    }
    while (sum >> 16) {
        sum = (sum & 0xffffu) + (sum >> 16);
    }

    {
        uint16_t r = (uint16_t)(~sum);
        return r ? r : 0xffffu;
    }
}

/* -------------------------------------------------------------------------
 * TAP write
 * ---------------------------------------------------------------------- */
static int tap_write(const uint8_t *data, DWORD len)
{
    OVERLAPPED ov;
    DWORD written = 0;
    BOOL ok;

    memset(&ov, 0, sizeof(ov));
    ov.hEvent = g_write_event;

    if (g_tap == INVALID_HANDLE_VALUE || g_write_event == NULL) {
        return 0;
    }

    ResetEvent(g_write_event);

    ok = WriteFile(g_tap, data, len, &written, &ov);
    if (!ok) {
        DWORD err = GetLastError();
        if (err != ERROR_IO_PENDING) {
            fprintf(stderr, "WriteFile failed: error %lu\n", err);
            return 0;
        }
        if (!GetOverlappedResult(g_tap, &ov, &written, TRUE)) {
            fprintf(stderr, "GetOverlappedResult(write) failed: error %lu\n", GetLastError());
            return 0;
        }
    }

    if (written != len) {
        fprintf(stderr, "Short write: %lu/%lu\n", (unsigned long)written, (unsigned long)len);
        return 0;
    }

    return 1;
}

/* -------------------------------------------------------------------------
 * Protocol parsers (display only)
 * ---------------------------------------------------------------------- */
static void parse_tcp(const uint8_t *p, size_t n)
{
    tcp_hdr_t t;

    if (n < sizeof(t)) {
        printf("TCP(truncated)\n");
        return;
    }

    memcpy(&t, p, sizeof(t));
    printf("TCP  %5u->%-5u [%s]\n",
           ntohs(t.src_port), ntohs(t.dst_port), tcp_flags_str(t.flags));
}

static void parse_udp(const uint8_t *p, size_t n)
{
    udp_hdr_t u;

    if (n < sizeof(u)) {
        printf("UDP(truncated)\n");
        return;
    }

    memcpy(&u, p, sizeof(u));
    printf("UDP  %5u->%-5u\n", ntohs(u.src_port), ntohs(u.dst_port));
}

static void parse_icmp(const uint8_t *p, size_t n)
{
    icmp_hdr_t ic;

    if (n < sizeof(ic)) {
        printf("ICMP(truncated)\n");
        return;
    }

    memcpy(&ic, p, sizeof(ic));
    printf("ICMP type=%-3u code=%u\n", ic.type, ic.code);
}

static void parse_transport(uint8_t proto, const uint8_t *p, size_t n)
{
    switch (proto) {
        case 1:  parse_icmp(p, n); break;
        case 6:  parse_tcp(p, n);  break;
        case 17: parse_udp(p, n);  break;
        case 58: printf("ICMPv6 type=%u\n", n > 0 ? p[0] : 0); break;
        default: printf("proto=%u\n", proto); break;
    }
}

static void parse_ipv4_payload(const uint8_t *p, size_t n)
{
    ipv4_hdr_t ip;
    uint8_t ihl;
    uint16_t total_len;
    char src[16], dst[16];

    if (n < sizeof(ip)) {
        printf("IPv4(truncated)\n");
        return;
    }

    memcpy(&ip, p, sizeof(ip));

    if ((ip.ver_ihl >> 4) != 4) {
        printf("IPv4(bad-version)\n");
        return;
    }

    ihl = (uint8_t)((ip.ver_ihl & 0x0f) * 4u);
    if (ihl < MIN_IPV4_HDR_LEN || n < ihl) {
        printf("IPv4(bad-ihl)\n");
        return;
    }

    total_len = ntohs(ip.total_len);
    if (total_len < ihl) {
        printf("IPv4(bad-total-len)\n");
        return;
    }
    if (total_len > n) {
        total_len = (uint16_t)n;
    }

    fmt_ipv4(src, sizeof(src), ip.src);
    fmt_ipv4(dst, sizeof(dst), ip.dst);

    printf("  IPv4  %-39s  %-39s  ttl=%-3u  ", src, dst, ip.ttl);

    if (total_len > ihl) {
        parse_transport(ip.proto, p + ihl, (size_t)(total_len - ihl));
    } else {
        printf("\n");
    }
}

static void parse_ipv6_payload(const uint8_t *p, size_t n)
{
    ipv6_hdr_t ip;
    uint16_t payload_len;
    size_t total_need;
    char src[40], dst[40];

    if (n < sizeof(ip)) {
        printf("IPv6(truncated)\n");
        return;
    }

    memcpy(&ip, p, sizeof(ip));

    if ((ip.ver_tc_hi >> 4) != 6) {
        printf("IPv6(bad-version)\n");
        return;
    }

    payload_len = ntohs(ip.payload_len);
    total_need = sizeof(ip) + (size_t)payload_len;
    if (total_need > n) {
        total_need = n;
    }

    fmt_ipv6(src, sizeof(src), ip.src);
    fmt_ipv6(dst, sizeof(dst), ip.dst);

    printf("  IPv6  %-39s  %-39s  hop=%-3u  ",
           src, dst, ip.hop_limit);

    if (total_need > sizeof(ip)) {
        parse_transport(ip.next_hdr, p + sizeof(ip), total_need - sizeof(ip));
    } else {
        printf("\n");
    }
}

static void parse_arp_payload(const uint8_t *p, size_t n)
{
    arp_hdr_t a;
    char src[16], dst[16];
    uint16_t op;

    if (n < sizeof(a)) {
        printf("ARP(truncated)\n");
        return;
    }

    memcpy(&a, p, sizeof(a));
    fmt_ipv4(src, sizeof(src), a.sender_ip);
    fmt_ipv4(dst, sizeof(dst), a.target_ip);
    op = ntohs(a.operation);

    printf("  ARP   %-39s  %-39s  %s\n",
           src, dst,
           op == 1 ? "REQ" : op == 2 ? "REP" : "?");
}

/* -------------------------------------------------------------------------
 * DHCP helpers
 * ---------------------------------------------------------------------- */
static int dhcp_options_have_cookie(const uint8_t *opts_base, size_t opts_len)
{
    static const uint8_t magic[4] = { 0x63, 0x82, 0x53, 0x63 };

    if (opts_len < 4) return 0;
    return memcmp(opts_base, magic, sizeof(magic)) == 0;
}

static uint8_t dhcp_msg_type(const uint8_t *opts, size_t len)
{
    size_t i = 0;

    while (i < len) {
        uint8_t code = opts[i];

        if (code == 255) break;
        if (code == 0) {
            i++;
            continue;
        }

        if (i + 1 >= len) break;

        {
            uint8_t olen = opts[i + 1];
            if (i + 2u + olen > len) break;

            if (code == 53 && olen >= 1) {
                return opts[i + 2];
            }

            i += 2u + olen;
        }
    }

    return 0;
}

static int build_dhcp_reply(const uint8_t *req_frame,
                            size_t req_len,
                            uint8_t msg_type,
                            uint8_t *buf,
                            size_t buf_len,
                            size_t *out_len)
{
    size_t eth_off = 0;
    size_t ip_off  = sizeof(eth_hdr_t);
    size_t udp_off;
    size_t dhcp_off;
    size_t opts_off;
    size_t opts_len;
    size_t udp_len;
    size_t ip_total;
    size_t frame_total;
    const eth_hdr_t  *req_eth;
    ipv4_hdr_t req_ip;
    udp_hdr_t req_udp;
    dhcp_hdr_t req_dhcp;
    uint8_t ihl;
    uint16_t ip_total_len;
    uint16_t req_udp_len;
    const uint8_t *req_opts_base;
    const uint8_t *opts;
    uint8_t mtype;
    uint8_t *p;
    size_t oi = 0;
    uint32_t lease_be;
    size_t dhcp_total;
    ipv4_hdr_t *ip;
    udp_hdr_t *udp;
    dhcp_hdr_t *dhcp;
    eth_hdr_t *eth;
    uint16_t udp_len16, ip_len16;

    if (!out_len) return 0;
    *out_len = 0;

    if (!range_ok(req_len, eth_off, sizeof(eth_hdr_t))) return 0;
    req_eth = (const eth_hdr_t *)(req_frame + eth_off);

    if (ntohs(req_eth->ethertype) != 0x0800) return 0;

    if (!range_ok(req_len, ip_off, sizeof(ipv4_hdr_t))) return 0;
    memcpy(&req_ip, req_frame + ip_off, sizeof(req_ip));

    if ((req_ip.ver_ihl >> 4) != 4) return 0;
    ihl = (uint8_t)((req_ip.ver_ihl & 0x0f) * 4u);
    if (ihl < MIN_IPV4_HDR_LEN) return 0;
    if (!range_ok(req_len, ip_off, ihl)) return 0;

    ip_total_len = ntohs(req_ip.total_len);
    if (ip_total_len < ihl + sizeof(udp_hdr_t)) return 0;
    if (ip_off + ip_total_len > req_len) {
        ip_total_len = (uint16_t)(req_len - ip_off);
    }

    if (req_ip.proto != 17) return 0;

    udp_off = ip_off + ihl;
    if (!range_ok(req_len, udp_off, sizeof(udp_hdr_t))) return 0;
    memcpy(&req_udp, req_frame + udp_off, sizeof(req_udp));

    if (ntohs(req_udp.src_port) != 68 || ntohs(req_udp.dst_port) != 67) return 0;

    req_udp_len = ntohs(req_udp.length);
    if (req_udp_len < sizeof(udp_hdr_t) + sizeof(dhcp_hdr_t) + 4u) return 0;
    if (udp_off + req_udp_len > req_len) {
        req_udp_len = (uint16_t)(req_len - udp_off);
    }

    dhcp_off = udp_off + sizeof(udp_hdr_t);
    if (!range_ok(req_len, dhcp_off, sizeof(req_dhcp))) return 0;
    memcpy(&req_dhcp, req_frame + dhcp_off, sizeof(req_dhcp));

    if (req_dhcp.op != 1 || req_dhcp.htype != 1 || req_dhcp.hlen != 6) return 0;

    req_opts_base = req_frame + dhcp_off + sizeof(req_dhcp);
    opts_len = req_len - (dhcp_off + sizeof(req_dhcp));
    if (!dhcp_options_have_cookie(req_opts_base, opts_len)) return 0;

    opts = req_opts_base + 4;
    opts_len -= 4;

    mtype = dhcp_msg_type(opts, opts_len);
    if ((msg_type == 2 && mtype != 1) || (msg_type == 5 && mtype != 3)) return 0;

    if (buf_len < 512u) return 0;
    memset(buf, 0, buf_len);

    p = buf + sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t) + sizeof(udp_hdr_t) + sizeof(dhcp_hdr_t);

    p[oi++] = 0x63; p[oi++] = 0x82; p[oi++] = 0x53; p[oi++] = 0x63;

    p[oi++] = 53; p[oi++] = 1; p[oi++] = msg_type;
    p[oi++] = 54; p[oi++] = 4; memcpy(p + oi, SERVER_IP, 4); oi += 4;

    lease_be = htonl(DHCP_LEASE_SECS);
    p[oi++] = 51; p[oi++] = 4; memcpy(p + oi, &lease_be, 4); oi += 4;

    p[oi++] = 1;  p[oi++] = 4; memcpy(p + oi, SUBNET, 4); oi += 4;
    p[oi++] = 3;  p[oi++] = 4; memcpy(p + oi, SERVER_IP, 4); oi += 4;
    p[oi++] = 6;  p[oi++] = 4; memcpy(p + oi, DNS_IP, 4); oi += 4;
    p[oi++] = 28; p[oi++] = 4; memcpy(p + oi, BROADCAST, 4); oi += 4;
    p[oi++] = 255;

    dhcp = (dhcp_hdr_t *)(buf + sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t) + sizeof(udp_hdr_t));
    memset(dhcp, 0, sizeof(*dhcp));
    dhcp->op    = 2;
    dhcp->htype = 1;
    dhcp->hlen  = 6;
    dhcp->xid   = req_dhcp.xid;
    dhcp->secs  = 0;
    dhcp->flags = req_dhcp.flags;
    memcpy(dhcp->yiaddr, CLIENT_IP, 4);
    memcpy(dhcp->siaddr, SERVER_IP, 4);
    memcpy(dhcp->chaddr, req_dhcp.chaddr, sizeof(dhcp->chaddr));
    memcpy((uint8_t *)dhcp + sizeof(*dhcp),
           buf + sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t) + sizeof(udp_hdr_t) + sizeof(*dhcp),
           oi);

    dhcp_total = sizeof(*dhcp) + oi;
    udp_len = sizeof(udp_hdr_t) + dhcp_total;
    ip_total = sizeof(ipv4_hdr_t) + udp_len;
    frame_total = sizeof(eth_hdr_t) + ip_total;

    if (frame_total > buf_len || udp_len > 0xffffu || ip_total > 0xffffu) return 0;

    udp_len16 = (uint16_t)udp_len;
    ip_len16 = (uint16_t)ip_total;

    udp = (udp_hdr_t *)(buf + sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t));
    memset(udp, 0, sizeof(*udp));
    udp->src_port = htons(67);
    udp->dst_port = htons(68);
    udp->length   = htons(udp_len16);
    udp->checksum = 0;

    ip = (ipv4_hdr_t *)(buf + sizeof(eth_hdr_t));
    memset(ip, 0, sizeof(*ip));
    ip->ver_ihl   = 0x45;
    ip->ttl       = 128;
    ip->proto     = 17;
    ip->total_len = htons(ip_len16);
    memcpy(ip->src, SERVER_IP, 4);
    memcpy(ip->dst, BROADCAST, 4);
    ip->checksum  = 0;
    ip->checksum  = checksum16(ip, sizeof(*ip));

    udp->checksum = 0;
    udp->checksum = transport_checksum_ipv4(ip->src, ip->dst, 17, udp, udp_len);

    eth = (eth_hdr_t *)buf;
    /* RFC 2131: if broadcast flag set, or client has no IP yet, use broadcast MAC */
    if (ntohs(req_dhcp.flags) & 0x8000u || memcmp(req_dhcp.ciaddr, "\0\0\0\0", 4) == 0) {
        memset(eth->dst, 0xff, 6);
    } else {
        memcpy(eth->dst, req_dhcp.chaddr, 6);
    }
    memcpy(eth->src, SERVER_MAC, 6);
    eth->ethertype = htons(0x0800);

    *out_len = frame_total;
    return 1;
}

static void send_dhcp_reply(const uint8_t *req_frame, size_t req_len, uint8_t msg_type)
{
    uint8_t buf[512];
    size_t out_len = 0;

    if (!build_dhcp_reply(req_frame, req_len, msg_type, buf, sizeof(buf), &out_len)) {
        return;
    }

    printf("        >> DHCP %s to ", msg_type == 2 ? "OFFER" : "ACK");
    print_ipv4(CLIENT_IP);
    printf(" (");
    print_mac(((const dhcp_hdr_t *)(req_frame + sizeof(eth_hdr_t) +
              ((((const ipv4_hdr_t *)(req_frame + sizeof(eth_hdr_t)))->ver_ihl & 0x0f) * 4u) +
              sizeof(udp_hdr_t)))->chaddr);
    printf(")\n");

    (void)tap_write(buf, (DWORD)out_len);
}

/* -------------------------------------------------------------------------
 * Reply to ARP Requests targeting SERVER_IP
 * ---------------------------------------------------------------------- */
static void maybe_handle_arp(const uint8_t *raw, size_t len)
{
    eth_hdr_t eth;
    arp_hdr_t req;
    uint8_t buf[sizeof(eth_hdr_t) + sizeof(arp_hdr_t)];
    eth_hdr_t *reth;
    arp_hdr_t *rep;

    if (!range_ok(len, 0, sizeof(eth) + sizeof(req))) return;

    memcpy(&eth, raw, sizeof(eth));
    if (ntohs(eth.ethertype) != 0x0806) return;

    memcpy(&req, raw + sizeof(eth), sizeof(req));

    if (ntohs(req.operation) != 1) return;
    if (ntohs(req.hw_type) != 1) return;
    if (ntohs(req.proto_type) != 0x0800) return;
    if (req.hw_len != 6 || req.proto_len != 4) return;
    if (memcmp(req.target_ip, SERVER_IP, 4) != 0) return;

    memset(buf, 0, sizeof(buf));

    reth = (eth_hdr_t *)buf;
    memcpy(reth->dst, req.sender_mac, 6);
    memcpy(reth->src, SERVER_MAC, 6);
    reth->ethertype = htons(0x0806);

    rep = (arp_hdr_t *)(buf + sizeof(eth_hdr_t));
    rep->hw_type    = htons(1);
    rep->proto_type = htons(0x0800);
    rep->hw_len     = 6;
    rep->proto_len  = 4;
    rep->operation  = htons(2);
    memcpy(rep->sender_mac, SERVER_MAC, 6);
    memcpy(rep->sender_ip,  SERVER_IP, 4);
    memcpy(rep->target_mac, req.sender_mac, 6);
    memcpy(rep->target_ip,  req.sender_ip, 4);

    printf("        >> ARP  ");
    print_ipv4(SERVER_IP);
    printf(" is-at ");
    print_mac(SERVER_MAC);
    printf("\n");

    (void)tap_write(buf, (DWORD)sizeof(buf));
}

/* -------------------------------------------------------------------------
 * Check an incoming frame for DHCP Discover/Request and respond
 * ---------------------------------------------------------------------- */
static void maybe_handle_dhcp(const uint8_t *raw, size_t len)
{
    eth_hdr_t eth;
    ipv4_hdr_t ip;
    udp_hdr_t udp;
    uint8_t ihl;
    size_t ip_off = sizeof(eth_hdr_t);
    size_t udp_off;
    size_t dhcp_off;
    uint16_t udp_len;
    size_t udp_payload_len;
    const uint8_t *opts_base;
    size_t opts_base_len;
    uint8_t mtype;

    if (!range_ok(len, 0, sizeof(eth))) return;
    memcpy(&eth, raw, sizeof(eth));
    if (ntohs(eth.ethertype) != 0x0800) return;

    if (!range_ok(len, ip_off, sizeof(ip))) return;
    memcpy(&ip, raw + ip_off, sizeof(ip));
    if ((ip.ver_ihl >> 4) != 4 || ip.proto != 17) return;

    ihl = (uint8_t)((ip.ver_ihl & 0x0f) * 4u);
    if (ihl < MIN_IPV4_HDR_LEN || !range_ok(len, ip_off, ihl)) return;

    udp_off = ip_off + ihl;
    if (!range_ok(len, udp_off, sizeof(udp))) return;
    memcpy(&udp, raw + udp_off, sizeof(udp));

    if (ntohs(udp.src_port) != 68 || ntohs(udp.dst_port) != 67) return;

    udp_len = ntohs(udp.length);
    if (udp_len < sizeof(udp) + sizeof(dhcp_hdr_t) + 4u) return;
    if (!range_ok(len, udp_off, udp_len)) return;

    dhcp_off = udp_off + sizeof(udp);
    if (!range_ok(len, dhcp_off, sizeof(dhcp_hdr_t))) return;

    udp_payload_len = (size_t)udp_len - sizeof(udp);
    if (udp_payload_len < DHCP_FIXED_PART_LEN) return;

    opts_base = raw + dhcp_off + sizeof(dhcp_hdr_t);
    opts_base_len = len - (dhcp_off + sizeof(dhcp_hdr_t));
    if (!dhcp_options_have_cookie(opts_base, opts_base_len)) return;

    mtype = dhcp_msg_type(opts_base + 4, opts_base_len - 4);
    if (mtype == 1) {
        send_dhcp_reply(raw, len, 2);
    } else if (mtype == 3) {
        send_dhcp_reply(raw, len, 5);
    }
}

/* -------------------------------------------------------------------------
 * Reply to TCP SYN with SYN-ACK so Windows completes the handshake
 *
 * To trigger TCP traffic: curl --max-time 3 http://<SERVER_IP>/
 * The program will reply with SYN-ACK; Windows sends ACK + HTTP GET.
 * ---------------------------------------------------------------------- */
static void maybe_handle_tcp_syn(const uint8_t *raw, size_t len)
{
    eth_hdr_t  eth;
    ipv4_hdr_t ip;
    tcp_hdr_t  tcp;
    uint8_t    ihl;
    size_t     ip_off  = sizeof(eth_hdr_t);
    size_t     tcp_off;
    uint8_t    buf[sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t) + sizeof(tcp_hdr_t)];
    eth_hdr_t  *reth;
    ipv4_hdr_t *rip;
    tcp_hdr_t  *rtcp;
    uint32_t   ack_num;

    if (!range_ok(len, 0, sizeof(eth))) return;
    memcpy(&eth, raw, sizeof(eth));
    if (ntohs(eth.ethertype) != 0x0800) return;

    if (!range_ok(len, ip_off, sizeof(ip))) return;
    memcpy(&ip, raw + ip_off, sizeof(ip));
    if ((ip.ver_ihl >> 4) != 4 || ip.proto != 6) return;

    ihl = (uint8_t)((ip.ver_ihl & 0x0f) * 4u);
    if (ihl < MIN_IPV4_HDR_LEN || !range_ok(len, ip_off, ihl)) return;

    tcp_off = ip_off + ihl;
    if (!range_ok(len, tcp_off, sizeof(tcp))) return;
    memcpy(&tcp, raw + tcp_off, sizeof(tcp));

    /* Only respond to pure SYN (flag 0x02), not SYN-ACK (0x12) */
    if ((tcp.flags & 0x17) != 0x02) return;

    memset(buf, 0, sizeof(buf));

    reth = (eth_hdr_t *)buf;
    memcpy(reth->dst, eth.src, 6);
    memcpy(reth->src, SERVER_MAC, 6);
    reth->ethertype = htons(0x0800);

    rip = (ipv4_hdr_t *)(buf + sizeof(eth_hdr_t));
    rip->ver_ihl   = 0x45;
    rip->ttl       = 64;
    rip->proto     = 6;
    rip->total_len = htons((uint16_t)(sizeof(ipv4_hdr_t) + sizeof(tcp_hdr_t)));
    memcpy(rip->src, ip.dst, 4);
    memcpy(rip->dst, ip.src, 4);
    rip->checksum  = checksum16(rip, sizeof(*rip));

    ack_num = ntohl(tcp.seq) + 1u;

    rtcp = (tcp_hdr_t *)(buf + sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t));
    rtcp->src_port = tcp.dst_port;
    rtcp->dst_port = tcp.src_port;
    rtcp->seq      = htonl(0x12345678u);
    rtcp->ack      = htonl(ack_num);
    rtcp->data_off = 0x50;   /* 5 * 4 = 20 bytes, no options */
    rtcp->flags    = 0x12;   /* SYN | ACK */
    rtcp->window   = htons(65535);
    rtcp->checksum = 0;
    rtcp->urgent   = 0;
    rtcp->checksum = transport_checksum_ipv4(rip->src, rip->dst, 6, rtcp, sizeof(*rtcp));

    printf("        >> TCP   SYN-ACK ");
    print_ipv4(ip.dst);
    printf(":%u -> ", ntohs(tcp.dst_port));
    print_ipv4(ip.src);
    printf(":%u\n", ntohs(tcp.src_port));

    (void)tap_write(buf, (DWORD)sizeof(buf));
}

/* -------------------------------------------------------------------------
 * Display a captured frame
 * ---------------------------------------------------------------------- */
static void process_frame(const uint8_t *raw, size_t len)
{
    eth_hdr_t eth;
    uint16_t et;
    const uint8_t *payload;
    size_t paylen;
    char smac[18], dmac[18];

    g_count++;

    if (len < sizeof(eth)) {
        printf("#%5d %5lu  (too short)\n", g_count, (unsigned long)len);
        return;
    }

    memcpy(&eth, raw, sizeof(eth));
    et = ntohs(eth.ethertype);

    fmt_mac(smac, sizeof(smac), eth.src);
    fmt_mac(dmac, sizeof(dmac), eth.dst);
    printf("#%5d %5lu  %-17s  %-17s",
           g_count, (unsigned long)len, smac, dmac);

    payload = raw + sizeof(eth);
    paylen  = len - sizeof(eth);

    if (et == 0x8100 && paylen >= 4) {
        uint16_t tci = read_be16(payload);
        uint16_t inner = read_be16(payload + 2);
        printf("  VLAN %u", tci & 0x0fffu);
        et = inner;
        payload += 4;
        paylen -= 4;
    }

    switch (et) {
        case 0x0800: parse_ipv4_payload(payload, paylen); break;
        case 0x86dd: parse_ipv6_payload(payload, paylen); break;
        case 0x0806: parse_arp_payload(payload, paylen);  break;
        default:     printf("  et=0x%04x\n", et); break;
    }

}

/* -------------------------------------------------------------------------
 * Registry: find TAP adapter GUID
 * ---------------------------------------------------------------------- */
static int find_tap_guid(char *guid_out, DWORD guid_out_len,
                         char *comp_out, DWORD comp_out_len)
{
    HKEY root;
    DWORD rc;
    char subname[64];
    DWORD idx = 0;
    int found = 0;

    rc = RegOpenKeyExA(HKEY_LOCAL_MACHINE, ADAPTER_REG_KEY, 0, KEY_READ, &root);
    if (rc != ERROR_SUCCESS) {
        fprintf(stderr, "Cannot open adapter registry key (need Admin?)\n");
        return 0;
    }

    while (!found) {
        DWORD namelen = (DWORD)_countof(subname);

        rc = RegEnumKeyExA(root, idx++, subname, &namelen, NULL, NULL, NULL, NULL);
        if (rc != ERROR_SUCCESS) break;

        {
            HKEY sub;
            rc = RegOpenKeyExA(root, subname, 0, KEY_READ, &sub);
            if (rc != ERROR_SUCCESS) continue;

            {
                char comp[128];
                DWORD comp_len = sizeof(comp);
                DWORD type = 0;

                rc = RegQueryValueExA(sub, "ComponentId", NULL, &type,
                                      (LPBYTE)comp, &comp_len);
                if (rc == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ)) {
                    char low[128];
                    size_t i;

                    comp[sizeof(comp) - 1] = '\0';
                    for (i = 0; i < sizeof(low) - 1 && comp[i] != '\0'; i++) {
                        low[i] = (char)tolower((unsigned char)comp[i]);
                    }
                    low[i] = '\0';

                    if (strstr(low, "tap") != NULL) {
                        DWORD glen = guid_out_len;
                        type = 0;
                        rc = RegQueryValueExA(sub, "NetCfgInstanceId", NULL, &type,
                                              (LPBYTE)guid_out, &glen);
                        if (rc == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ)) {
                            guid_out[guid_out_len - 1] = '\0';
                            strncpy_s(comp_out, comp_out_len, comp, _TRUNCATE);
                            found = 1;
                        }
                    }
                }
            }

            RegCloseKey(sub);
        }
    }

    RegCloseKey(root);
    return found;
}

/* -------------------------------------------------------------------------
 * Ctrl-C
 * ---------------------------------------------------------------------- */
static BOOL WINAPI ctrl_handler(DWORD type)
{
    (void)type;
    InterlockedExchange(&g_stop, 1);
    return TRUE;
}

/* -------------------------------------------------------------------------
 * main
 * ---------------------------------------------------------------------- */
int main(int argc, char *argv[])
{
    WSADATA wsa;
    int frame_limit = 0;
    char guid[128] = {0};
    char comp[128] = {0};
    char path[256];
    ULONG ver[3] = {0};
    DWORD rlen = 0;
    ULONG status = 1;
    OVERLAPPED ov;
    static uint8_t frame_buf[MAX_FRAME_LEN];
    int captured = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-x") == 0) {
            g_hex_dump = 1;
            /* collapse so remaining parsing doesn't see it */
            for (int j = i; j < argc - 1; j++) argv[j] = argv[j + 1];
            argc--;
            i--;
        }
    }

    if (argc >= 2 && strchr(argv[1], '.') != NULL) {
        unsigned a, b, c, d;
        if (sscanf(argv[1], "%u.%u.%u.%u", &a, &b, &c, &d) == 4 &&
            a <= 255u && b <= 255u && c <= 255u && d <= 255u) {
            CLIENT_IP[0] = (uint8_t)a;
            CLIENT_IP[1] = (uint8_t)b;
            CLIENT_IP[2] = (uint8_t)c;
            CLIENT_IP[3] = (uint8_t)d;
            SERVER_IP[0] = (uint8_t)a;
            SERVER_IP[1] = (uint8_t)b;
            SERVER_IP[2] = (uint8_t)c;
            SERVER_IP[3] = 1;
        } else {
            fprintf(stderr, "Invalid IP '%s'\n", argv[1]);
            return 1;
        }
    }

    if (argc >= 3) {
        frame_limit = atoi(argv[2]);
    } else if (argc >= 2 && strchr(argv[1], '.') == NULL) {
        frame_limit = atoi(argv[1]);
    }

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    if (!SetConsoleCtrlHandler(ctrl_handler, TRUE)) {
        fprintf(stderr, "SetConsoleCtrlHandler failed: %lu\n", GetLastError());
        WSACleanup();
        return 1;
    }

    if (!find_tap_guid(guid, sizeof(guid), comp, sizeof(comp))) {
        fprintf(stderr, "No TAP-Windows adapter found (need Admin? OpenVPN installed?)\n");
        WSACleanup();
        return 1;
    }

    printf("TAP adapter  ComponentId : %s\n", comp);
    printf("             GUID        : %s\n\n", guid);

    _snprintf_s(path, sizeof(path), _TRUNCATE, "\\\\.\\Global\\%s.tap", guid);
    printf("Opening %s\n", path);

    g_tap = CreateFileA(path,
                        GENERIC_READ | GENERIC_WRITE,
                        0, NULL, OPEN_EXISTING,
                        FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
                        NULL);
    if (g_tap == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "CreateFile failed: error %lu\n", GetLastError());
        WSACleanup();
        return 1;
    }

    g_write_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (g_write_event == NULL) {
        fprintf(stderr, "CreateEvent(write) failed: error %lu\n", GetLastError());
        CloseHandle(g_tap);
        WSACleanup();
        return 1;
    }

    if (DeviceIoControl(g_tap, TAP_WIN_IOCTL_GET_VERSION,
                        ver, sizeof(ver), ver, sizeof(ver), &rlen, NULL)) {
        printf("TAP driver version : %lu.%lu.%lu\n", ver[0], ver[1], ver[2]);
    }

    if (!DeviceIoControl(g_tap, TAP_WIN_IOCTL_SET_MEDIA_STATUS,
                         &status, sizeof(status), &status, sizeof(status), &rlen, NULL)) {
        fprintf(stderr, "SET_MEDIA_STATUS failed: %lu\n", GetLastError());
        CloseHandle(g_write_event);
        CloseHandle(g_tap);
        WSACleanup();
        return 1;
    }

    printf("Link status        : UP\n");
    printf("DHCP server        : "); print_ipv4(SERVER_IP); printf("\n");
    printf("Will offer         : "); print_ipv4(CLIENT_IP); printf(" /24\n");
    printf("Capturing%s (Ctrl-C to stop)...\n\n", frame_limit ? " (limited)" : "");
    printf("%6s %5s  %-17s  %-17s  %-4s  %-39s  %-39s  %-7s  %s\n",
           "#", "len", "src MAC", "dst MAC", "L3", "src addr", "dst addr", "ttl/hop", "L4");
    printf("%6s %5s  %-17s  %-17s  %-4s  %-39s  %-39s  %-7s  %s\n",
           "------", "-----",
           "-----------------", "-----------------",
           "----",
           "---------------------------------------",
           "---------------------------------------",
           "-------", "--");

    memset(&ov, 0, sizeof(ov));
    ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (ov.hEvent == NULL) {
        fprintf(stderr, "CreateEvent(read) failed: error %lu\n", GetLastError());
        status = 0;
        DeviceIoControl(g_tap, TAP_WIN_IOCTL_SET_MEDIA_STATUS,
                        &status, sizeof(status), &status, sizeof(status), &rlen, NULL);
        CloseHandle(g_write_event);
        CloseHandle(g_tap);
        WSACleanup();
        return 1;
    }

    while (!InterlockedCompareExchange(&g_stop, 0, 0) &&
           (frame_limit == 0 || captured < frame_limit)) {
        DWORD nread = 0;
        BOOL ok;

        ResetEvent(ov.hEvent);

        ok = ReadFile(g_tap, frame_buf, (DWORD)sizeof(frame_buf), &nread, &ov);
        if (!ok) {
            DWORD err = GetLastError();

            if (err == ERROR_IO_PENDING) {
                DWORD wait_rc = WaitForSingleObject(ov.hEvent, 500);
                if (wait_rc == WAIT_TIMEOUT) {
                    continue;
                }
                if (wait_rc != WAIT_OBJECT_0) {
                    fprintf(stderr, "WaitForSingleObject failed: %lu\n", GetLastError());
                    break;
                }
                if (!GetOverlappedResult(g_tap, &ov, &nread, FALSE)) {
                    fprintf(stderr, "GetOverlappedResult(read) failed: %lu\n", GetLastError());
                    break;
                }
            } else {
                fprintf(stderr, "ReadFile failed: error %lu\n", err);
                break;
            }
        }

        if (nread > 0) {
            process_frame(frame_buf, (size_t)nread);
            maybe_handle_arp(frame_buf, (size_t)nread);
            maybe_handle_dhcp(frame_buf, (size_t)nread);
            maybe_handle_tcp_syn(frame_buf, (size_t)nread);
            if (g_hex_dump)
                hex_dump(frame_buf, (size_t)nread);
            captured++;
        }
    }

    status = 0;
    (void)DeviceIoControl(g_tap, TAP_WIN_IOCTL_SET_MEDIA_STATUS,
                          &status, sizeof(status), &status, sizeof(status), &rlen, NULL);

    CloseHandle(ov.hEvent);
    CloseHandle(g_write_event);
    CloseHandle(g_tap);
    WSACleanup();

    printf("\nDone. %d frame(s) captured.\n", g_count);
    return 0;
}