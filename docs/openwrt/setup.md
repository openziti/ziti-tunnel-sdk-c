Setup Ziti Edge Tunnel on Teltonica RUT240
------------------------------------------

# Download and install
1. get ziti-edge-tunnel bundle from https://ziti-public.s3.us-east-2.amazonaws.com/mips-teltonica/ziti-edge-tunnel-Linux_mips.zip
1. unzip and copy `ziti-edge-tunnel` executable to `/usr/sbin` (location could be different with appropriate adjustments to init script) 
1. get [ziti init script](ziti.init) and modify if needed
1. put [init script](ziti.init) as `/etc/init.d/ziti`

# Configure Ziti identity
1. create folder '/etc/ziti'
1. copy CA auto-enrollment JWT as `/etc/ziti/ca.jwt`
1. generate unique device SSL client certificate and copy to '/etc/ziti' along with private key:
   - key should be saved as `/etc/ziti/id.key`
   - certificate should be saved as `/etc/ziti/id.crt`

# Configure Ziti service to autostart
`# /etc/init.d/ziti enable`
The first time ziti service starts it enrolls with controller specified by `ca.jwt`

# Alternative enrollment
It is possible to enroll with OTT (one time token) JWT manually.
- create endpoint in MOP and download enrollment key -- JWT file
- move JWT file to the device somewhere (e.g. `/tmp/enroll.jwt`)
- enroll with the following command:  
  `# /usr/sbin/ziti-edge-tunnel enroll -j /tmp/enroll.jwt -i /etc/ziti/id.json`
- this create `/etc/ziti/id.json` file and ziti service can be started normally or automatically on next power up

