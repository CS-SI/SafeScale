#!/usr/bin/env bash

#mount device to repository
mkfs.{{.Fsformat}} {{.Device}}
mkdir -p {{.MountPoint}}

#configure fstab
echo "{{.Device}} {{.MountPoint}} {{.Fsformat}} defaults 0 2" >> /etc/fstab
mount -a
chmod a+rw {{.MountPoint}}
