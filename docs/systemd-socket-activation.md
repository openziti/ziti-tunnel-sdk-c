systemd socket activation:
==========================

For systemd socket activation, we need systemd to start and manage both the command and events sockets on behalf of the ziti-edge-tunnel:

`/etc/systemd/system/ziti-edge-tunnel.socket`: 

```ini
[Socket]
ListenStream=/tmp/.ziti/ziti-edge-tunnel.sock
ListenStream=/tmp/.ziti/ziti-edge-tunnel-event.sock
SocketUser=ziti
SocketGroup=ziti
DirectoryMode=750
RemoveOnStop=true


[Install]
WantedBy=sockets.target
```

Additionally, these additional settings override make the experience nice in terms of startup sequencing and lifetime.

`/etc/systemd/system/ziti-edge-tunnel.service.d/override.conf`:

```ini
[Unit]
CollectMode=inactive-or-failed
BindsTo=ziti-edge-tunnel.socket
After=ziti-edge-tunnel.socket
```

Ziti Desktop Edge Integration:
------------------------------

Integration with the `ziti-console` can be achieved like this:

`/usr/share/application/zitidesktopedge.desktop`: 

```ini
[Desktop Entry]
Name=Ziti Desktop Edge Debug
Exec=sudo /usr/bin/sh -c "/usr/bin/systemd-run --uid=$SUDO_USER --gid=ziti --setenv=DISPLAY=$DISPLAY --setenv=XAUTHORITY=$XAUTHORITY /usr/bin/zitidesktopedge"
Type=Application
Icon=zitidesktopedge
Comment=Ziti Desktop Edge Debug
Categories=Utility;
```

For this to work, you need a `sudo` rule to authorize the above command like this:

`/etc/sudoers.d/zde`:

```
%ziti ALL=(ALL) NOPASSWD: /bin/sh -c /usr/bin/systemd-run*zitidesktopedge
```

Finally, ensure that your login user is in the `ziti` group. 

`sudo usermod -a -G ziti "$USER"`

NOTE: you might need to log out and back in to ensure your user is in the group for your desktop session.
