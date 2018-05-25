#!/usr/bin/env bash
#
# nfs_client_share_unmount.sh
#
# Unconfigures and unmounts a remote access to a NFS share

umount -fl {{.Host}}:{{.Share}}
sed -i '\#^{{.Host}}:{{.Share}}#d' /etc/fstab
