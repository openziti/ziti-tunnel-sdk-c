# BPF filter for pcap driver

## Problem

Without a filter, every Ethernet frame on the capture adapter flows through the full
pipeline: copied from kernel to userspace, malloc'd into a `frame_node_t`, queued,
`uv_async_send` fired, dequeued on the libuv thread, passed to `on_packet`, and finally
discarded by `tunneler_l2_get_conn` because the ethtype isn't `0x8892`.  On a busy Wi-Fi
adapter this is ~200 frames/sec of pure waste.

## What a BPF filter does

BPF runs inside the Npcap kernel driver.  The filter expression is compiled to bytecode
and evaluated before any frame is copied to userspace.  Frames that don't match are
dropped at the driver level — zero allocation, zero queue, zero wakeup.

## Filter expression

```
ether proto 0x8892
```

This matches PROFINET DCP (and all other PROFINET frames — RT, RTA, PTCPv2 etc. all share
ethtype 0x8892).  Nothing else gets through.

## Implementation in pcap.c

Two more functions need to be resolved from `wpcap.dll` via `GetProcAddress`:

```c
struct bpf_program;   /* forward-declare or define minimally */

typedef int  (*fn_pcap_compile_t)(pcap_t *, struct bpf_program *, const char *, int, uint32_t);
typedef int  (*fn_pcap_setfilter_t)(pcap_t *, struct bpf_program *);
typedef void (*fn_pcap_freecode_t)(struct bpf_program *);
```

After `pcap_open_live` succeeds in `ziti_pcap_open`:

```c
struct bpf_program fp;
if (dyn_pcap_compile(pcap, &fp, "ether proto 0x8892", 1, 0xffffffff) == 0) {
    dyn_pcap_setfilter(pcap, &fp);
    dyn_pcap_freecode(&fp);
    ZITI_LOG(INFO, "pcap: BPF filter applied: ether proto 0x8892");
} else {
    ZITI_LOG(WARN, "pcap: pcap_compile failed: %s -- capturing all frames",
             dyn_pcap_geterr(pcap));
}
```

The `struct bpf_program` layout must match what wpcap.dll expects.  The portable way is to
include `<pcap/bpf.h>` from the Npcap SDK, but since we're going SDK-free we need the
struct definition.  From libpcap source:

```c
struct bpf_insn {
    uint16_t code;
    uint8_t  jt;
    uint8_t  jf;
    uint32_t k;
};

struct bpf_program {
    uint32_t         bf_len;
    struct bpf_insn *bf_insns;
};
```

This is stable — it hasn't changed since BSD and is part of the ABI.

## Implementation in rawsock_windows.c (dcp tools)

Same pattern.  After `pcap_open_live` in `rawsock_open`, apply the same filter.  For the
dcp tools it's optional (they're interactive, short-lived, low traffic) but it makes
`rawsock_recv` less noisy since it won't surface IPv4/IPv6 traffic as potential DCP
responses.

## Caveat: filter is on the pcap handle, not the adapter

The filter applies only to frames delivered to this process.  Other processes (Wireshark,
the OS network stack) are unaffected.  Injected frames via `pcap_sendpacket` bypass the
filter entirely — outbound is always unfiltered.

## Alternative: filter at the tunneler layer

`tunneler_l2_get_conn` already drops non-0x8892 frames after the fact.  The BPF filter is
purely a performance optimisation — it's not required for correctness.  If adding
`struct bpf_program` SDK-free feels fragile, the simpler fix is to add a hardcoded ethtype
check in the reader thread before queuing:

```c
/* inside pcap_reader_thread, after caplen check */
if (hdr->caplen >= 14) {
    uint16_t et = (data[12] << 8) | data[13];
    if (et != 0x8892) continue;  /* drop non-PROFINET */
}
```

This costs one branch per frame in userspace but avoids the BPF struct dependency.  Still
much cheaper than queuing and async-waking for every frame.
