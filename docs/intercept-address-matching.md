# Intercept Address Matching

Tunneler SDK versions 0.18.16 and earlier would associate incoming packets with the first
service that had a matching intercept address to the packet's destination proto:ip:port.
Now the tSDK associates packets with the ziti service that has the most precisely matching
intercept address. "precision" is defined as follows:

- ip addresses with higher prefixes are more precise than those with lower prefixes
- exact hostnames are more precise than wildcard domains
- smaller port ranges are more precise than larger port ranges
- an ip address or hostname match of any precision is more significant than a port range match

For example, consider an identity that has "Dial" access to the following services:

| service       | addresses      | ports   | protocols |
|---------------|----------------|---------|-----------|
| ziti-subnet   | 192.168.0.0/16 | 1-65535 | tcp,udp   |
| ziti-ip       | 192.168.10.88  | 8080    | tcp,udp   |
| ziti-hostname | host.ziti      | 8080    | tcp       |
| ziti-wildname | *.ziti         | 1-65535 | tcp       |

And the tSDK's internal DNS server is populated with the following mappings:

| ip          | hostname  | description                                                    |
|-------------|-----------|----------------------------------------------------------------|
| 100.64.0.10 | host.ziti | from `ziti-hostname` configuration                             |
| 100.64.0.11 | wh1.ziti  | from `ziti-wildname` configuration, after "wh1.ziti" dns query |
| 100.64.0.12 | wh2.ziti  | from `ziti-wildname` configuration, after "wh2.ziti" dns query |

The following packet <--> service associations will be made:

| intercepted proto:ip:port | best match    | reason                                                              |
|---------------------------|---------------|---------------------------------------------------------------------|
| tcp:192.168.10.88:8080    | ziti-ip       | exact match on ip address and port                                  |
| tcp:192.168.10.88:9090    | ziti-subnet   | `ziti-ip` is overlooked despite exact ip match due to port mismatch |
| tcp:100.64.0.11:443       | ziti-wildname | exact IP match and within port range                                |
| tcp:100.64.0.10:9090      | none          | no service with matching address/port combination                   |
