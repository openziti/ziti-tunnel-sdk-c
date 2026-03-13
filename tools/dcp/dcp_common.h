/*
 * dcp_common.h - Shared PROFINET DCP protocol definitions.
 *
 * Used by both dcp_identify and dcp_respond.
 */

#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define ETH_P_PROFINET         0x8892u
#define DCP_FRAME_ID_IDENT_REQ 0xFEFEu
#define DCP_FRAME_ID_IDENT_RSP 0xFEFFu

/* DCP service IDs */
#define DCP_SVC_IDENTIFY       0x05
/* DCP service types */
#define DCP_SVCTYPE_REQUEST    0x00
#define DCP_SVCTYPE_RESPONSE   0x01

/* Block option/suboption values */
#define DCP_OPT_IP             0x01
#define DCP_SUB_IP_ADDR        0x01
#define DCP_OPT_DEVICE         0x02
#define DCP_SUB_DEVICE_NAME    0x01
#define DCP_SUB_DEVICE_VENDOR  0x02
#define DCP_OPT_ALL            0xFF
#define DCP_SUB_ALL            0xFF

/* PROFINET DCP multicast MAC: 01:0e:cf:00:00:00 */
static const uint8_t DCP_MCAST_MAC[6] = {0x01, 0x0e, 0xcf, 0x00, 0x00, 0x00};

#pragma pack(push, 1)

typedef struct {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t ethertype;  /* network byte order */
} eth_hdr_t;

typedef struct {
    uint16_t frame_id;       /* network byte order */
    uint8_t  service_id;
    uint8_t  service_type;
    uint32_t xid;            /* network byte order */
    uint16_t response_delay; /* network byte order; "reserved" in responses */
    uint16_t dcp_data_len;   /* network byte order */
} dcp_hdr_t;

typedef struct {
    uint8_t  option;
    uint8_t  suboption;
    uint16_t block_len;      /* network byte order: includes 2-byte block_info */
} dcp_blk_t;

#pragma pack(pop)

/* ---------- helpers ---------- */

static inline uint16_t dcp_u16(uint16_t v) {
#if defined(_WIN32) || defined(__APPLE__) || defined(__linux__)
    /* portable byte swap — compilers optimize this to bswap */
    return (uint16_t)((v >> 8) | (v << 8));
#endif
}

static inline uint32_t dcp_u32(uint32_t v) {
    return ((v & 0x000000ffu) << 24) |
           ((v & 0x0000ff00u) <<  8) |
           ((v & 0x00ff0000u) >>  8) |
           ((v & 0xff000000u) >> 24);
}

/* hton / ntoh wrappers that work without <arpa/inet.h> on Windows */
#ifdef _WIN32
#  include <winsock2.h>
#  define DCP_HTONS(x) htons(x)
#  define DCP_NTOHS(x) ntohs(x)
#  define DCP_HTONL(x) htonl(x)
#  define DCP_NTOHL(x) ntohl(x)
#else
#  include <arpa/inet.h>
#  define DCP_HTONS(x) htons(x)
#  define DCP_NTOHS(x) ntohs(x)
#  define DCP_HTONL(x) htonl(x)
#  define DCP_NTOHL(x) ntohl(x)
#endif

static inline void print_mac(const uint8_t *m) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", m[0],m[1],m[2],m[3],m[4],m[5]);
}

/*
 * Append a DCP block: 4-byte header + 2-byte block_info + data.
 * Returns updated byte position in buf.
 */
static inline int dcp_append_block(uint8_t *buf, int pos,
                                    uint8_t opt, uint8_t sub,
                                    const uint8_t *data, uint16_t datalen)
{
    uint16_t block_len = (uint16_t)(2 + datalen); /* block_info (2) + data */
    buf[pos++] = opt;
    buf[pos++] = sub;
    buf[pos++] = (uint8_t)(block_len >> 8);
    buf[pos++] = (uint8_t)(block_len & 0xff);
    buf[pos++] = 0x00; /* block_info hi */
    buf[pos++] = 0x00; /* block_info lo */
    memcpy(buf + pos, data, datalen);
    pos += datalen;
    if (block_len & 1) buf[pos++] = 0x00; /* pad to even */
    return pos;
}
