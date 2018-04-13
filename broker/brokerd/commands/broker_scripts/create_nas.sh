#!/usr/bin/env bash

echo "install nfs server"
apt-get update && apt-get install -qqy nfs-common nfs-kernel-server && apt-get clean && rm -rf /var/lib/apt/lists/*

echo "Create exported dir if necessary"
mkdir -p {{.ExportedPath}}

echo "Export diretory"
echo "{{.ExportedPath}} *(rw,fsid=1,sync,no_root_squash)" >>/etc/exports
/etc/init.d/nfs-kernel-server restart