# Put safescale as a service

`safescaled` can be turned easily as a linux service using `systemd` in a few single steps:

 - copy SafeScale binaries (ie `safescale` and `safescaled`) into `/usr/local/bin`
 - create the service definition inside `/lib/systemd/system/safescale.service`:

```
[Unit]
Description=SafeScale daemon 
Requires=network.target
After=multi-user.target

[Service]
Type=simple
ExecStart=/usr/local/bin/safescaled

[Install]
WantedBy=multi-user.target
```
 - create the serice socket inside `/lib/systemd/system/safescale.socket`:

```
[Socket]
ListenStream=127.0.0.1:50051

[Install]
WantedBy=sockets.target
```

 - enable the service:

```
systemctl enable safescale.service
```
