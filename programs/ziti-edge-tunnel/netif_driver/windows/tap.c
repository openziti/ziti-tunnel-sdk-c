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

/*
 * tap.c - TAP-Windows L2 netif driver for ziti-edge-tunnel (Windows)
 *
 * Opens the first TAP-Windows adapter found in the registry and exposes it as
 * a netif_driver, delivering raw Ethernet frames to the lwIP stack via the
 * on_packet callback.  Routes are managed through the Windows MIB API
 * (same approach as the wintun driver).
 *
 * Requires: Administrator privileges, TAP-Windows driver installed
 * (OpenVPN 2.x community installer or tap-windows6 standalone package).
 */

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <winioctl.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <netioapi.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>

#include <ziti/netif_driver.h>
#include <ziti/ziti_log.h>
#include <ziti/model_support.h>

#include "tap.h"

/* -------------------------------------------------------------------------
 * TAP-Windows IOCTLs
 * ---------------------------------------------------------------------- */
#define TAP_WIN_CONTROL_CODE(req, method) \
    CTL_CODE(FILE_DEVICE_UNKNOWN, (req), (method), FILE_ANY_ACCESS)

#define TAP_WIN_IOCTL_GET_MAC           TAP_WIN_CONTROL_CODE(1, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_GET_VERSION       TAP_WIN_CONTROL_CODE(2, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_GET_MTU           TAP_WIN_CONTROL_CODE(3, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_SET_MEDIA_STATUS  TAP_WIN_CONTROL_CODE(6, METHOD_BUFFERED)

#define ADAPTER_REG_KEY \
    "SYSTEM\\CurrentControlSet\\Control\\Class\\" \
    "{4D36E972-E325-11CE-BFC1-08002BE10318}"

#define MAX_FRAME_LEN 65536u

/* -------------------------------------------------------------------------
 * Internal frame queue node (reader thread -> libuv async callback)
 * ---------------------------------------------------------------------- */
typedef struct frame_node {
    size_t len;
    struct frame_node *next;
    uint8_t data[1]; /* allocated with extra space for the actual frame bytes */
} frame_node_t;

/* -------------------------------------------------------------------------
 * netif_handle
 * ---------------------------------------------------------------------- */
struct netif_handle_s {
    char name[MAX_ADAPTER_NAME]; /* friendly adapter name */
    char guid[128];              /* NetCfgInstanceId from registry, e.g. {XXXX-...} */
    NET_LUID luid;               /* resolved from guid; used for MIB route API */

    HANDLE tap;                  /* device handle (\\.\\Global\\{guid}.tap) */
    HANDLE read_event;           /* OVERLAPPED event for ReadFile */
    HANDLE write_event;          /* OVERLAPPED event for WriteFile */

    volatile LONG stopping;

    uv_thread_t reader;
    uv_async_t *read_available;  /* signals libuv loop that frames are queued */

    uv_mutex_t frame_lock;
    frame_node_t *frame_head;
    frame_node_t *frame_tail;

    packet_cb on_packet;
    void *netif;
};

/* forward declarations */
static int tap_close(struct netif_handle_s *tun);

/* -------------------------------------------------------------------------
 * Registry: find first TAP-Windows adapter GUID + friendly name
 * ---------------------------------------------------------------------- */
static int find_tap_adapter(char *guid_out, DWORD guid_out_len,
                             char *name_out, DWORD name_out_len)
{
    HKEY root;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, ADAPTER_REG_KEY, 0, KEY_READ, &root) != ERROR_SUCCESS) {
        return 0;
    }

    int found = 0;
    char subname[64];
    for (DWORD idx = 0; !found; idx++) {
        DWORD namelen = (DWORD)sizeof(subname);
        if (RegEnumKeyExA(root, idx, subname, &namelen, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
            break;
        }

        HKEY sub;
        if (RegOpenKeyExA(root, subname, 0, KEY_READ, &sub) != ERROR_SUCCESS) {
            continue;
        }

        char comp[128];
        DWORD comp_len = sizeof(comp), type = 0;
        LSTATUS rc = RegQueryValueExA(sub, "ComponentId", NULL, &type, (LPBYTE)comp, &comp_len);
        if (rc == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ)) {
            comp[sizeof(comp) - 1] = '\0';

            /* lower-case comparison so we match tap0901, tapwindows6, etc. */
            char low[128];
            size_t i;
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

                    if (name_out && name_out_len > 0) {
                        DWORD nlen = name_out_len;
                        type = 0;
                        rc = RegQueryValueExA(sub, "NetConnectionId", NULL, &type,
                                              (LPBYTE)name_out, &nlen);
                        if (rc != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ) ||
                            name_out[0] == '\0') {
                            strncpy_s(name_out, name_out_len, comp, _TRUNCATE);
                        }
                        name_out[name_out_len - 1] = '\0';
                    }
                    found = 1;
                }
            }
        }
        RegCloseKey(sub);
    }

    RegCloseKey(root);
    return found;
}

/* -------------------------------------------------------------------------
 * Parse GUID string (with or without braces) into a GUID struct.
 * Avoids a dependency on Ole32/IIDFromString.
 * ---------------------------------------------------------------------- */
static int parse_guid_str(const char *s, GUID *out)
{
    if (*s == '{') s++; /* skip optional leading brace */
    unsigned int d0, d1, d2, d3, d4, d5, d6, d7, d8, d9, d10;
    if (sscanf_s(s, "%8x-%4x-%4x-%2x%2x-%2x%2x%2x%2x%2x%2x",
                 &d0, &d1, &d2, &d3, &d4,
                 &d5, &d6, &d7, &d8, &d9, &d10) != 11) {
        return -1;
    }
    out->Data1    = d0;
    out->Data2    = (WORD)d1;
    out->Data3    = (WORD)d2;
    out->Data4[0] = (BYTE)d3; out->Data4[1] = (BYTE)d4;
    out->Data4[2] = (BYTE)d5; out->Data4[3] = (BYTE)d6;
    out->Data4[4] = (BYTE)d7; out->Data4[5] = (BYTE)d8;
    out->Data4[6] = (BYTE)d9; out->Data4[7] = (BYTE)d10;
    return 0;
}

/* -------------------------------------------------------------------------
 * Route helpers — same MIB API pattern as the wintun driver
 * ---------------------------------------------------------------------- */
static int parse_route(PIP_ADDRESS_PREFIX pfx, const char *route)
{
    int ip[4], bits;
    int rc = sscanf_s(route, "%d.%d.%d.%d/%d",
                      &ip[0], &ip[1], &ip[2], &ip[3], &bits);
    if (rc < 4) {
        ZITI_LOG(WARN, "invalid route spec[%s]", route);
        return -1;
    }
    pfx->PrefixLength = (rc == 4) ? 32 : (UINT8)bits;
    pfx->Prefix.Ipv4.sin_family = AF_INET;
    pfx->Prefix.Ipv4.sin_addr.S_un.S_addr =
        (ULONG)(ip[0]) | ((ULONG)ip[1] << 8) | ((ULONG)ip[2] << 16) | ((ULONG)ip[3] << 24);
    return 0;
}

typedef DWORD(__stdcall *route_f)(const MIB_IPFORWARD_ROW2 *);

static DWORD tap_do_route(netif_handle tun, const char *dest, route_f rt_f)
{
    MIB_IPFORWARD_ROW2 rt;
    InitializeIpForwardEntry(&rt);
    rt.InterfaceLuid = tun->luid;
    if (parse_route(&rt.DestinationPrefix, dest) != 0) {
        return ERROR_INVALID_PARAMETER;
    }
    return rt_f(&rt);
}

static int tap_add_route(netif_handle tun, const char *dest)
{
    ZITI_LOG(DEBUG, "tap: adding route %s", dest);
    DWORD rc = tap_do_route(tun, dest, CreateIpForwardEntry2);
    if (rc != 0 && rc != ERROR_OBJECT_ALREADY_EXISTS) {
        ZITI_LOG(WARN, "tap: failed to add route '%s': %lu", dest, rc);
    }
    return 0;
}

static int tap_del_route(netif_handle tun, const char *dest)
{
    ZITI_LOG(DEBUG, "tap: deleting route %s", dest);
    DWORD rc = tap_do_route(tun, dest, DeleteIpForwardEntry2);
    if (rc != 0) {
        ZITI_LOG(WARN, "tap: failed to delete route '%s': %lu", dest, rc);
    }
    return 0;
}

static int tap_exclude_rt(netif_handle dev, uv_loop_t *loop, const char *dest)
{
    /* Not needed for L2 tunneling — return success */
    (void)dev; (void)loop; (void)dest;
    return 0;
}

static const char *tap_get_name(netif_handle tun)
{
    return tun->name;
}

/* -------------------------------------------------------------------------
 * Write: overlapped WriteFile to the TAP device
 * ---------------------------------------------------------------------- */
static ssize_t tap_write(netif_handle tun, const void *buf, size_t len)
{
    OVERLAPPED ov = {0};
    ov.hEvent = tun->write_event;
    ResetEvent(tun->write_event);

    DWORD written = 0;
    BOOL ok = WriteFile(tun->tap, buf, (DWORD)len, &written, &ov);
    if (!ok) {
        DWORD err = GetLastError();
        if (err == ERROR_IO_PENDING) {
            if (!GetOverlappedResult(tun->tap, &ov, &written, TRUE)) {
                ZITI_LOG(ERROR, "tap: write GetOverlappedResult failed: %lu", GetLastError());
                return -1;
            }
        } else {
            ZITI_LOG(ERROR, "tap: WriteFile failed: %lu", err);
            return -1;
        }
    }
    return (ssize_t)written;
}

/* -------------------------------------------------------------------------
 * Frame parsing / logging  (adapted from capture.c)
 * ---------------------------------------------------------------------- */

#pragma pack(push, 1)
typedef struct { uint8_t dst[6], src[6]; uint16_t ethertype; } tap_eth_hdr_t;
typedef struct {
    uint8_t  ver_ihl, dscp_ecn;
    uint16_t total_len, id, flags_frag;
    uint8_t  ttl, proto;
    uint16_t checksum;
    uint8_t  src[4], dst[4];
} tap_ipv4_hdr_t;
typedef struct {
    uint8_t  ver_tc_hi, tc_lo_fl_hi;
    uint16_t fl_lo, payload_len;
    uint8_t  next_hdr, hop_limit;
    uint8_t  src[16], dst[16];
} tap_ipv6_hdr_t;
typedef struct {
    uint16_t hw_type, proto_type;
    uint8_t  hw_len, proto_len;
    uint16_t operation;
    uint8_t  sender_mac[6], sender_ip[4], target_mac[6], target_ip[4];
} tap_arp_hdr_t;
typedef struct {
    uint16_t src_port, dst_port;
    uint32_t seq, ack;
    uint8_t  data_off, flags;
    uint16_t window, checksum, urgent;
} tap_tcp_hdr_t;
typedef struct { uint16_t src_port, dst_port, length, checksum; } tap_udp_hdr_t;
typedef struct { uint8_t type, code; uint16_t checksum; }         tap_icmp_hdr_t;
#pragma pack(pop)

#define TAP_APPEND(buf_, pos_, size_, ...) \
    do { int _n = snprintf((buf_)+(pos_), (size_t)(size_)-(pos_), __VA_ARGS__); \
         if (_n > 0) (pos_) += _n; } while(0)

static int tap_range_ok(size_t total, size_t off, size_t need) {
    return off <= total && need <= total - off;
}

static void tap_fmt_mac(char *b, size_t bsz, const uint8_t *a) {
    snprintf(b, bsz, "%02x:%02x:%02x:%02x:%02x:%02x",
             a[0], a[1], a[2], a[3], a[4], a[5]);
}
static void tap_fmt_ip4(char *b, size_t bsz, const uint8_t *a) {
    snprintf(b, bsz, "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
}
static void tap_fmt_ip6(char *b, size_t bsz, const uint8_t *a) {
    snprintf(b, bsz,
             "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
             "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
             a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7],
             a[8],a[9],a[10],a[11],a[12],a[13],a[14],a[15]);
}

static void tap_fmt_transport(char *buf, int bufsz, int *pos,
                               uint8_t proto, const uint8_t *p, size_t n)
{
    tap_tcp_hdr_t  tcp;
    tap_udp_hdr_t  udp;
    tap_icmp_hdr_t ic;
    switch (proto) {
        case 1:
            if (n < sizeof(ic)) { TAP_APPEND(buf,*pos,bufsz,"ICMP(trunc)"); break; }
            memcpy(&ic, p, sizeof(ic));
            TAP_APPEND(buf,*pos,bufsz,"ICMP type=%u code=%u", ic.type, ic.code);
            break;
        case 6:
            if (n < sizeof(tcp)) { TAP_APPEND(buf,*pos,bufsz,"TCP(trunc)"); break; }
            memcpy(&tcp, p, sizeof(tcp));
            TAP_APPEND(buf,*pos,bufsz,"TCP %u->%u [%s%s%s%s%s]",
                       ntohs(tcp.src_port), ntohs(tcp.dst_port),
                       (tcp.flags & 0x02) ? "SYN " : "",
                       (tcp.flags & 0x10) ? "ACK " : "",
                       (tcp.flags & 0x01) ? "FIN " : "",
                       (tcp.flags & 0x04) ? "RST " : "",
                       (tcp.flags & 0x08) ? "PSH " : "");
            break;
        case 17:
            if (n < sizeof(udp)) { TAP_APPEND(buf,*pos,bufsz,"UDP(trunc)"); break; }
            memcpy(&udp, p, sizeof(udp));
            TAP_APPEND(buf,*pos,bufsz,"UDP %u->%u", ntohs(udp.src_port), ntohs(udp.dst_port));
            break;
        case 58:
            if (n > 0) TAP_APPEND(buf,*pos,bufsz,"ICMPv6 type=%u", p[0]);
            else       TAP_APPEND(buf,*pos,bufsz,"ICMPv6");
            break;
        default:
            TAP_APPEND(buf,*pos,bufsz,"proto=%u", proto);
            break;
    }
}

static void tap_fmt_ipv4(char *buf, int bufsz, int *pos, const uint8_t *p, size_t n)
{
    tap_ipv4_hdr_t ip;
    if (n < sizeof(ip)) { TAP_APPEND(buf,*pos,bufsz,"IPv4(trunc)"); return; }
    memcpy(&ip, p, sizeof(ip));
    if ((ip.ver_ihl >> 4) != 4) { TAP_APPEND(buf,*pos,bufsz,"IPv4(bad-ver)"); return; }
    uint8_t ihl = (uint8_t)((ip.ver_ihl & 0x0f) * 4u);
    if (ihl < 20 || n < ihl) { TAP_APPEND(buf,*pos,bufsz,"IPv4(bad-ihl)"); return; }
    uint16_t total = ntohs(ip.total_len);
    if (total > n) total = (uint16_t)n;
    char src[16], dst[16];
    tap_fmt_ip4(src, sizeof(src), ip.src);
    tap_fmt_ip4(dst, sizeof(dst), ip.dst);
    TAP_APPEND(buf,*pos,bufsz,"IPv4 %s -> %s ttl=%u ", src, dst, ip.ttl);
    if (total > ihl)
        tap_fmt_transport(buf, bufsz, pos, ip.proto, p + ihl, (size_t)(total - ihl));
}

static void tap_fmt_ipv6(char *buf, int bufsz, int *pos, const uint8_t *p, size_t n)
{
    tap_ipv6_hdr_t ip;
    if (n < sizeof(ip)) { TAP_APPEND(buf,*pos,bufsz,"IPv6(trunc)"); return; }
    memcpy(&ip, p, sizeof(ip));
    if ((ip.ver_tc_hi >> 4) != 6) { TAP_APPEND(buf,*pos,bufsz,"IPv6(bad-ver)"); return; }
    uint16_t plen = ntohs(ip.payload_len);
    size_t avail = n - sizeof(ip);
    if (plen > avail) plen = (uint16_t)avail;
    char src[40], dst[40];
    tap_fmt_ip6(src, sizeof(src), ip.src);
    tap_fmt_ip6(dst, sizeof(dst), ip.dst);
    TAP_APPEND(buf,*pos,bufsz,"IPv6 %s -> %s hop=%u ", src, dst, ip.hop_limit);
    if (plen > 0)
        tap_fmt_transport(buf, bufsz, pos, ip.next_hdr, p + sizeof(ip), plen);
}

static void tap_fmt_arp(char *buf, int bufsz, int *pos, const uint8_t *p, size_t n)
{
    tap_arp_hdr_t a;
    if (n < sizeof(a)) { TAP_APPEND(buf,*pos,bufsz,"ARP(trunc)"); return; }
    memcpy(&a, p, sizeof(a));
    char src[16], dst[16];
    tap_fmt_ip4(src, sizeof(src), a.sender_ip);
    tap_fmt_ip4(dst, sizeof(dst), a.target_ip);
    uint16_t op = ntohs(a.operation);
    TAP_APPEND(buf,*pos,bufsz,"ARP %s -> %s %s",
               src, dst, op == 1 ? "REQ" : op == 2 ? "REP" : "?");
}

static void tap_hex_dump(const uint8_t *data, size_t len)
{
    char row[80];
    for (size_t i = 0; i < len; i += 16) {
        int pos = 0;
        TAP_APPEND(row, pos, sizeof(row), "  %04zx  ", i);
        size_t end = i + 16 < len ? i + 16 : len;
        for (size_t j = i; j < end; j++)
            TAP_APPEND(row, pos, sizeof(row), "%02x ", data[j]);
        for (size_t j = end; j < i + 16; j++)
            TAP_APPEND(row, pos, sizeof(row), "   ");
        TAP_APPEND(row, pos, sizeof(row), " |");
        for (size_t j = i; j < end; j++)
            TAP_APPEND(row, pos, sizeof(row), "%c",
                       (data[j] >= 0x20 && data[j] < 0x7f) ? data[j] : '.');
        ZITI_LOG(VERBOSE, "%s", row);
    }
}

static void tap_log_frame(const uint8_t *raw, size_t len)
{
    char buf[256];
    int pos = 0;

    if (!tap_range_ok(len, 0, sizeof(tap_eth_hdr_t))) {
        ZITI_LOG(VERBOSE, "tap rx: (too short, %zu bytes)", len);
        return;
    }

    tap_eth_hdr_t eth;
    memcpy(&eth, raw, sizeof(eth));
    uint16_t et = ntohs(eth.ethertype);

    char smac[18], dmac[18];
    tap_fmt_mac(smac, sizeof(smac), eth.src);
    tap_fmt_mac(dmac, sizeof(dmac), eth.dst);
    TAP_APPEND(buf, pos, sizeof(buf), "tap rx: len=%-5zu %s -> %s  ", len, smac, dmac);

    const uint8_t *payload = raw + sizeof(tap_eth_hdr_t);
    size_t paylen = len - sizeof(tap_eth_hdr_t);

    if (et == 0x8100 && paylen >= 4) {
        uint16_t tci   = (uint16_t)((payload[0] << 8) | payload[1]);
        uint16_t inner = (uint16_t)((payload[2] << 8) | payload[3]);
        TAP_APPEND(buf, pos, sizeof(buf), "VLAN %u  ", tci & 0x0fffu);
        et      = inner;
        payload += 4;
        paylen  -= 4;
    }

    switch (et) {
        case 0x0800: tap_fmt_ipv4(buf, sizeof(buf), &pos, payload, paylen); break;
        case 0x86dd: tap_fmt_ipv6(buf, sizeof(buf), &pos, payload, paylen); break;
        case 0x0806: tap_fmt_arp (buf, sizeof(buf), &pos, payload, paylen); break;
        default:     TAP_APPEND(buf, pos, sizeof(buf), "et=0x%04x", et);   break;
    }

    ZITI_LOG(VERBOSE, "%s", buf);
    tap_hex_dump(raw, len);
}

/* -------------------------------------------------------------------------
 * Frame delivery: called on the libuv event loop thread via uv_async_t
 * ---------------------------------------------------------------------- */
static void tap_deliver_frames(uv_async_t *ar)
{
    netif_handle tun = ar->data;

    for (;;) {
        uv_mutex_lock(&tun->frame_lock);
        frame_node_t *node = tun->frame_head;
        if (node) {
            tun->frame_head = node->next;
            if (tun->frame_head == NULL) {
                tun->frame_tail = NULL;
            }
        }
        uv_mutex_unlock(&tun->frame_lock);

        if (node == NULL) break;

        tap_log_frame(node->data, node->len);
        tun->on_packet((const char *)node->data, (ssize_t)node->len, tun->netif);
        free(node);
    }
}

/* -------------------------------------------------------------------------
 * Reader thread: blocking overlapped reads, queues frames for libuv
 * ---------------------------------------------------------------------- */
static void tap_reader(void *h)
{
    netif_handle tun = h;
    static uint8_t frame_buf[MAX_FRAME_LEN];

    OVERLAPPED ov = {0};
    ov.hEvent = tun->read_event;

    while (!InterlockedCompareExchange(&tun->stopping, 0, 0)) {
        DWORD nread = 0;
        ResetEvent(ov.hEvent);

        BOOL ok = ReadFile(tun->tap, frame_buf, (DWORD)sizeof(frame_buf), &nread, &ov);
        if (!ok) {
            DWORD err = GetLastError();
            if (err == ERROR_IO_PENDING) {
                DWORD wait = WaitForSingleObject(ov.hEvent, 500 /* ms timeout to check stopping flag */);
                if (wait == WAIT_TIMEOUT) continue;
                if (wait != WAIT_OBJECT_0) break;
                if (!GetOverlappedResult(tun->tap, &ov, &nread, FALSE)) {
                    /* handle is closing or IO was cancelled */
                    break;
                }
            } else if (err == ERROR_OPERATION_ABORTED) {
                break; /* CancelIo was called during close */
            } else {
                ZITI_LOG(ERROR, "tap: ReadFile failed: %lu", err);
                break;
            }
        }

        if (nread == 0) continue;

        frame_node_t *node = malloc(offsetof(frame_node_t, data) + nread);
        if (!node) {
            ZITI_LOG(ERROR, "tap: OOM dropping frame of %lu bytes", nread);
            continue;
        }
        node->len  = nread;
        node->next = NULL;
        memcpy(node->data, frame_buf, nread);

        uv_mutex_lock(&tun->frame_lock);
        if (tun->frame_tail) {
            tun->frame_tail->next = node;
        } else {
            tun->frame_head = node;
        }
        tun->frame_tail = node;
        uv_mutex_unlock(&tun->frame_lock);

        uv_async_send(tun->read_available);
    }
}

/* -------------------------------------------------------------------------
 * setup_read: spawn the reader thread and wire up the async handle
 * ---------------------------------------------------------------------- */
static int tap_setup_read(netif_handle tun, uv_loop_t *loop,
                           packet_cb on_packet, void *netif)
{
    tun->on_packet = on_packet;
    tun->netif     = netif;

    tun->read_available = calloc(1, sizeof(uv_async_t));
    if (!tun->read_available) return -1;

    uv_async_init(loop, tun->read_available, tap_deliver_frames);
    tun->read_available->data = tun;

    uv_thread_create(&tun->reader, tap_reader, tun);
    return 0;
}

/* -------------------------------------------------------------------------
 * Close
 * ---------------------------------------------------------------------- */
static int tap_close(struct netif_handle_s *tun)
{
    if (tun == NULL) return 0;

    InterlockedExchange(&tun->stopping, 1);

    if (tun->tap != INVALID_HANDLE_VALUE) {
        /* Cancel any pending overlapped read so the reader thread unblocks */
        CancelIo(tun->tap);

        /* Bring link down */
        ULONG status = 0;
        DWORD rlen = 0;
        DeviceIoControl(tun->tap, TAP_WIN_IOCTL_SET_MEDIA_STATUS,
                        &status, sizeof(status), &status, sizeof(status), &rlen, NULL);

        CloseHandle(tun->tap);
        tun->tap = INVALID_HANDLE_VALUE;
    }

    if (tun->read_event)  { CloseHandle(tun->read_event);  tun->read_event  = NULL; }
    if (tun->write_event) { CloseHandle(tun->write_event); tun->write_event = NULL; }

    /* drain any queued frames */
    uv_mutex_lock(&tun->frame_lock);
    frame_node_t *n = tun->frame_head;
    tun->frame_head = tun->frame_tail = NULL;
    uv_mutex_unlock(&tun->frame_lock);
    while (n) { frame_node_t *next = n->next; free(n); n = next; }

    uv_mutex_destroy(&tun->frame_lock);
    free(tun);
    return 0;
}

/* -------------------------------------------------------------------------
 * tap_open
 * ---------------------------------------------------------------------- */
netif_driver tap_open(uv_loop_t *loop, uint32_t tun_ip, const char *cidr,
                      char *error, size_t error_len)
{
    if (error) memset(error, 0, error_len);

    struct netif_handle_s *tun = calloc(1, sizeof(*tun));
    if (!tun) {
        snprintf(error, error_len, "failed to allocate tap handle");
        return NULL;
    }
    tun->tap = INVALID_HANDLE_VALUE;

    /* ---- discover adapter ---- */
    if (!find_tap_adapter(tun->guid, sizeof(tun->guid), tun->name, sizeof(tun->name))) {
        snprintf(error, error_len,
                 "no TAP-Windows adapter found (need Admin? tap-windows6/OpenVPN installed?)");
        free(tun);
        return NULL;
    }
    ZITI_LOG(INFO, "tap: found adapter name='%s' guid='%s'", tun->name, tun->guid);

    /* ---- resolve NET_LUID from GUID (needed for MIB route/address APIs) ---- */
    {
        GUID g = {0};
        if (parse_guid_str(tun->guid, &g) == 0) {
            if (ConvertInterfaceGuidToLuid(&g, &tun->luid) != NO_ERROR) {
                ZITI_LOG(WARN, "tap: ConvertInterfaceGuidToLuid failed: %lu — route management may fail",
                         GetLastError());
            }
        } else {
            ZITI_LOG(WARN, "tap: could not parse adapter GUID '%s'", tun->guid);
        }
    }

    /* ---- open device ---- */
    char path[256];
    _snprintf_s(path, sizeof(path), _TRUNCATE, "\\\\.\\Global\\%s.tap", tun->guid);
    ZITI_LOG(INFO, "tap: opening %s", path);

    tun->tap = CreateFileA(path,
                           GENERIC_READ | GENERIC_WRITE,
                           0, NULL, OPEN_EXISTING,
                           FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
                           NULL);
    if (tun->tap == INVALID_HANDLE_VALUE) {
        snprintf(error, error_len, "CreateFile(%s) failed: %lu", path, GetLastError());
        free(tun);
        return NULL;
    }

    tun->read_event  = CreateEventW(NULL, TRUE, FALSE, NULL);
    tun->write_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!tun->read_event || !tun->write_event) {
        snprintf(error, error_len, "CreateEvent failed: %lu", GetLastError());
        tap_close(tun);
        return NULL;
    }

    /* ---- log driver version ---- */
    ULONG ver[3] = {0};
    DWORD rlen = 0;
    if (DeviceIoControl(tun->tap, TAP_WIN_IOCTL_GET_VERSION,
                        ver, sizeof(ver), ver, sizeof(ver), &rlen, NULL)) {
        ZITI_LOG(INFO, "tap: driver version %lu.%lu.%lu", ver[0], ver[1], ver[2]);
    }

    /* ---- bring link UP ---- */
    ULONG status = 1;
    if (!DeviceIoControl(tun->tap, TAP_WIN_IOCTL_SET_MEDIA_STATUS,
                         &status, sizeof(status), &status, sizeof(status), &rlen, NULL)) {
        snprintf(error, error_len, "TAP_WIN_IOCTL_SET_MEDIA_STATUS(UP) failed: %lu", GetLastError());
        tap_close(tun);
        return NULL;
    }
    ZITI_LOG(INFO, "tap: link UP");

    /* ---- allocate driver struct ---- */
    struct netif_driver_s *driver = calloc(1, sizeof(*driver));
    if (!driver) {
        snprintf(error, error_len, "failed to allocate netif_driver_s");
        tap_close(tun);
        return NULL;
    }

    /* ---- set IPv4 address via MIB API ---- */
    {
        MIB_UNICASTIPADDRESS_ROW row;
        InitializeUnicastIpAddressEntry(&row);
        row.InterfaceLuid = tun->luid;
        row.Address.Ipv4.sin_family = AF_INET;
        row.Address.Ipv4.sin_addr.S_un.S_addr = tun_ip;
        if (cidr) {
            int ip[4], bits;
            if (sscanf_s(cidr, "%d.%d.%d.%d/%d", &ip[0], &ip[1], &ip[2], &ip[3], &bits) >= 5) {
                row.OnLinkPrefixLength = (UINT8)bits;
            } else {
                row.OnLinkPrefixLength = 24;
            }
        } else {
            row.OnLinkPrefixLength = 24;
        }
        DWORD err = CreateUnicastIpAddressEntry(&row);
        if (err != ERROR_SUCCESS && err != ERROR_OBJECT_ALREADY_EXISTS) {
            ZITI_LOG(WARN, "tap: CreateUnicastIpAddressEntry failed: %lu (continuing)", err);
        }
    }

    /* ---- read hardware address and MTU via TAP-Windows IOCTLs ---- */
    {
        uint8_t mac[6] = {0};
        ULONG mtu = 1500;
        if (DeviceIoControl(tun->tap, TAP_WIN_IOCTL_GET_MAC,
                            mac, sizeof(mac), mac, sizeof(mac), &rlen, NULL) && rlen == 6) {
            memcpy(driver->hwaddr, mac, 6);
            driver->hwaddr_len = 6;
            ZITI_LOG(INFO, "tap: hwaddr %02x:%02x:%02x:%02x:%02x:%02x",
                     mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        } else {
            ZITI_LOG(WARN, "tap: TAP_WIN_IOCTL_GET_MAC failed (%lu) — L2 mode may not work correctly",
                     GetLastError());
        }
        if (DeviceIoControl(tun->tap, TAP_WIN_IOCTL_GET_MTU,
                            &mtu, sizeof(mtu), &mtu, sizeof(mtu), &rlen, NULL)) {
            driver->mtu = (uint16_t)(mtu < 65535u ? mtu : 1500u);
            ZITI_LOG(INFO, "tap: mtu=%u", driver->mtu);
        } else {
            driver->mtu = 1500;
            ZITI_LOG(WARN, "tap: TAP_WIN_IOCTL_GET_MTU failed (%lu) — using default mtu=%u",
                     GetLastError(), driver->mtu);
        }
        driver->ip4addr.s_addr = tun_ip;
    }

    uv_mutex_init(&tun->frame_lock);

    driver->handle       = tun;
    driver->setup        = tap_setup_read;
    driver->write        = tap_write;
    driver->add_route    = tap_add_route;
    driver->delete_route = tap_del_route;
    driver->close        = tap_close;
    driver->exclude_rt   = tap_exclude_rt;
    driver->get_name     = tap_get_name;

    return driver;
}
