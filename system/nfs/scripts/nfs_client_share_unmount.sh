#!/usr/bin/env bash
#
# nfs_client_share_unmount.sh
#
# Unconfigures and unmounts a remote access to a NFS share

umount -fl {{.MountPoint}}
grep -v "^{{.Host}}:{{.Share}} " /etc/fstab >/etc/fstab.new
mv /etc/fstab.new /etc/fstab
