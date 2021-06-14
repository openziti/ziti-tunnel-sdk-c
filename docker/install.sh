# transparent install procedure for ziti-edge-tunnel

# where to install the executable binary
ZITI_EDGE_TUNNEL_BIN_DIR=/usr/local/bin

# where to look at startup for enrolled identity JSON config files
if [[ ! -z ${XDG_DATA_HOME:-} ]]; then 
    ZITI_EDGE_TUNNEL_ID_DIR="${XDG_DATA_HOME}/.ziti-edge-tunnel"
else
    ZITI_EDGE_TUNNEL_ID="${HOME}/.ziti-edge-tunnel"
fi

ZITI_EDGE_TUNNEL_ID_DIR=~/.ziti-edge-tunnel

# create the identity directory
❯ mkdir -pvm0700 $ZITI_EDGE_TUNNEL_ID_DIR

# create a systemd service
❯ cat <<ZITI_SERVICE | sudo tee /usr/lib/systemd/system/ziti-edge-tunnel.service                
[Unit]
Description=Ziti Edge Tunnel
After=network.target
ConditionDirectoryNotEmpty=$ZITI_EDGE_TUNNEL_ID_DIR

[Service]
User=root
ExecStart=${ZITI_EDGE_TUNNEL_BIN_DIR}/ziti-edge-tunnel run --verbose 4 --identity-dir $ZITI_EDGE_TUNNEL_ID_DIR
Restart=always
RestartSec=2
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
ZITI_SERVICE

# load the new systemd config
❯ sudo systemctl daemon-reload

# download some version of ziti-edge-tunnel
❯ curl -sSLf https://raw.githubusercontent.com/openziti/ziti-tunnel-sdk-c/main/docker/fetch-github-releases.sh | ZITI_VERSION=0.17.7 bash -x /dev/stdin ziti-edge-tunnel

# install in a directory that is in the executable search PATH
❯ sudo mv -v ./ziti-edge-tunnel ${ZITI_EDGE_TUNNEL_BIN_DIR}/

# verify the installed version
❯ sudo ziti-edge-tunnel version

# use a downloaded enrollment token to generate an identity
❯ sudo ziti-edge-tunnel enroll --jwt ~/Downloads/linuxTunneler1.jwt --identity ${ZITI_EDGE_TUNNEL_ID_DIR}/linuxTunneler1.json

# start the daemon
❯ sudo systemctl start ziti-edge-tunnel.service

# view the logs
❯ sudo journalctl -lfu ziti-edge-tunnel.service
