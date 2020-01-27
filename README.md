# API Notes

The ziti tunneler SDK dispatches layer 3 packets to ziti service connections.
Using the SDK, a tunneler application only needs to proxy layer 3
packets from a virtual NIC (typically a tun interface)

typedef void (*to_client_cb)(uint8_t *packet, size_t len)

- `NF_tunnel_init(to_client_cb)`


implement the following callbacks:

- `on_service_add(const char *, intercept_address)`
  `on_service_del(const char *, intercept_address)`

  These functions are called when a service is added to an appwan.
  Implementing applications should establish routes to the virtual
  NIC for the intercept address of the added service.



- `to_ziti(uint8_t *packet, size_t len)`

  Implementing applications must call this function when a packet is
  read from the virtual NIC.


- `to_client(uint8_t *packet, size_t len)`

  This function is called by the SDK when data is received from a
  connected ziti service. The implementing application should write
  the packet to the virtual NIC.


# Design Notes

## Packet Flow

The tunneler application adds a handle to the same uv loop that drives events
for the Ziti SDK. The handle will most likely be a `poll` handle that reads
the packet device. Packet devices are OS-specific (e.g. file descriptor
on Linux (darwin?), stream socket on Windows)
