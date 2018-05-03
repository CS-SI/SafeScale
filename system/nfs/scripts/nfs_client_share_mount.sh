#!/usr/bin/env bash
#
# nfs_client_share_mount.sh
#
# Declares a remote share mount and mount it

mkdir -p "{{.MountPoint}}"
mount -o noac "{{.Host}}:{{.Share}}" "{{.MountPoint}"
echo "{{.Host}}:{{.Share} {{.MountPoint}}   nfs defaults,user,auto,noatime,intr,noac 0   0" >>/etc/fstab
exit 0