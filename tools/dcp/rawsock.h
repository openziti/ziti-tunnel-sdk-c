/*
 * rawsock.h - platform-agnostic raw Ethernet socket abstraction.
 *
 * Linux  : AF_PACKET
 * macOS  : BPF (/dev/bpf*)
 * Windows: TAP-Windows device (first adapter found in registry)
 *
 * On Windows the ifname argument to rawsock_open() is ignored;
 * the first TAP adapter is used automatically.
 */

#pragma once
#include <stdint.h>
#include <stddef.h>

typedef struct rawsock_s rawsock_t;

/* Open a raw Ethernet socket on the named interface.
 * Returns NULL on failure; error message written to error/errlen. */
rawsock_t *rawsock_open(const char *ifname, char *error, size_t errlen);

void rawsock_close(rawsock_t *rs);

/* Send a complete Ethernet frame (including Ethernet header).
 * Returns 0 on success, -1 on error. */
int rawsock_send(rawsock_t *rs, const uint8_t *frame, size_t len);

/* Receive one Ethernet frame into buf.
 * timeout_ms: >0 = wait at most that many ms, 0 = block forever.
 * Returns frame length, 0 on timeout, -1 on error. */
int rawsock_recv(rawsock_t *rs, uint8_t *buf, size_t buflen, int timeout_ms);

/* Get the MAC address of the bound interface. */
void rawsock_get_mac(rawsock_t *rs, uint8_t mac[6]);
