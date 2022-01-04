# Put safescale as a service

> **Warning**: By default, service is run as "root". Placement of file "tenants.toml" must follow these rules:
> If service is run as **root**, must be at "/etc/safescale/tenants.toml"
> If service is run as an **user**, can be at "/etc/safescale/tenants.toml", or "[**user homedir**]/.safescale/tenants.toml" or "[**user homedir**]/.config/safescale/tenants.toml" 

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
# User=root

[Install]
WantedBy=multi-user.target
```
 - create the service socket inside `/lib/systemd/system/safescale.socket`:

```
[Socket]
ListenStream=127.0.0.1:50051

[Install]
WantedBy=sockets.target
```

 - enable the service:

```
systemctl enable safescale.service
systemctl start safescale
```

