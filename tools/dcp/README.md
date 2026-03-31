# DCP Test Tools

Two small programs for testing PROFINET DCP (Discovery and Configuration Protocol) over raw
Ethernet. Useful for validating L2 tunneling before connecting real PLCs.

- **`dcp_identify`** — sends a DCP Identify All broadcast and prints responses
- **`dcp_respond`** — listens for DCP Identify broadcasts and replies with a fake device

Supports **Linux** (AF_PACKET), **macOS** (BPF), and **Windows** (TAP-Windows / tap0901).

---

## Build

### CMake (all platforms — recommended)

```bash
cd tools/dcp
cmake -B build
cmake --build build
```

Binaries land in `build/` (Linux/macOS) or `build\Debug\` / `build\Release\` (Windows/MSVC).

On Windows with a generator that puts configs in subfolders add `--config Release` to the build
command:

```cmd
cmake -B build
cmake --build build --config Release
```

### Quick one-liner (Linux only, no CMake)

```bash
cd tools/dcp
gcc -o dcp_identify dcp_identify.c rawsock_linux.c
gcc -o dcp_respond  dcp_respond.c  rawsock_linux.c
```

---

## Run

Both programs take the network interface name as their only argument and require raw socket
access. On Windows the interface argument is **ignored** — the first TAP-Windows adapter found
in the registry is used automatically.

### Linux / macOS

**Responder** (run on the "PLC" machine first):
```bash
sudo ./dcp_respond eth0
```

**Identifier** (run on the "engineering PC"):
```bash
sudo ./dcp_identify eth0
```

Replace `eth0` with whatever interface is on your LAN (`ip link` to list them on Linux;
`ifconfig` on macOS).

### Windows

Windows requires the [OpenVPN TAP-Windows driver](https://build.openvpn.net/downloads/releases/)
(`tap-windows-*.exe`) to be installed. Any version with component ID `tap0901` works; the
OpenVPN community installer includes one.

Run **without** elevation or `sudo` from a normal Command Prompt (the TAP device is already
accessible):

```cmd
build\Release\dcp_respond.exe
```
```cmd
build\Release\dcp_identify.exe
```

To run both on the **same Windows machine** use two separate TAP adapters. Install a second
adapter with `addtap.bat` (found in the OpenVPN install directory), then both programs will each
open one adapter automatically. Alternatively, bridge the TAP adapter to your physical LAN NIC
via `ncpa.cpl` → select both → right-click → Bridge Connections, then run `dcp_identify.exe`
from inside WSL2 (which will use the bridged physical interface).

---

## Expected Output

**Responder side:**
```
Listening on eth0 (mac=aa:bb:cc:dd:ee:ff)
  station-name : fake-plc-1
  vendor       : FakeCo
  ip           : 192.168.1.200

  identify request from 11:22:33:44:55:66  xid=0xdeadbeef  -> responding
```

**Identifier side:**
```
Sent DCP Identify All on eth0 (src=11:22:33:44:55:66)
Waiting 3s for responses...

  device aa:bb:cc:dd:ee:ff  xid=0xdeadbeef
    station-name : fake-plc-1
    vendor       : FakeCo
    ip/mask/gw   : 192.168.1.200 / 255.255.255.0 / 0.0.0.0

Done.
```

---

## Customising the Fake Device

Edit the constants near the top of `dcp_respond.c`:

```c
static const char    *STATION_NAME  = "fake-plc-1";
static const char    *VENDOR_NAME   = "FakeCo";
static const uint8_t  DEVICE_IP[4]   = {192, 168, 1, 200};
static const uint8_t  DEVICE_MASK[4] = {255, 255, 255,   0};
static const uint8_t  DEVICE_GW[4]   = {  0,   0,   0,   0};
```

---

## Testing on the Same Linux Machine (veth pair)

AF_PACKET sockets only see the RX path — frames sent by another process on the same interface
are invisible to other local sockets. Use a **veth pair** (a virtual Ethernet cable between two
local interfaces):

```bash
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth0 up
sudo ip link set veth1 up

sudo ./dcp_respond  veth0 &
sudo ./dcp_identify veth1

# clean up
sudo ip link del veth0
```

---

## macOS Notes

- Requires `sudo` because opening `/dev/bpf*` needs root.
- The interface name is the BSD name shown in `ifconfig` output, e.g. `en0`, `en1`.
- No extra packages needed — BPF is built into macOS.

---

## WSL2 Notes

WSL2 uses a virtual network adapter (`eth0`) that is NAT'd — it is **not** directly on your
physical LAN. Raw PROFINET frames sent from WSL2 will not reach other machines on your LAN.

Options:
- Run on a native Linux machine or VM with bridged networking.
- Use WSL1 (shares the Windows network stack directly).
- On Windows, run the native `dcp_identify.exe` / `dcp_respond.exe` via the TAP adapter once
  the L2 tunnel is working.

---

## Architecture

```
dcp_identify.c  ──┐
dcp_respond.c   ──┤──► rawsock.h (interface)
                  │
                  ├──► rawsock_linux.c   (AF_PACKET)
                  ├──► rawsock_macos.c   (BPF /dev/bpfN)
                  └──► rawsock_windows.c (TAP-Windows tap0901)
```

`dcp_common.h` holds shared DCP protocol structs, constants, and helper functions used by both
programs.
