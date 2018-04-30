#!/usr/bin/env bash

echo "install nfs client"
apt-get update && apt-get install -qqy nfs-common && apt-get clean && rm -rf /var/lib/apt/lists/*

echo "Create mount dir if necessary"
mkdir -p {{.MountPath}}

echo "{{.NFSServer}}:{{.ExportedPath}}/   {{.MountPath}}  nfs defaults,user,auto,noatime,intr,noac 0   0" >> /etc/fstab
mount -o noacl "{{.NFSServer}}:/{{.ExportedPath}}" "{{.MountPath}}"