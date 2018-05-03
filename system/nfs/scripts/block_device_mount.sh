#!/usr/bin/env bash
#
# block_device_mount.sh
# Creates a filesystem on a device and mounts it

# Create filesystem
mkfs -t {{.FileSystem}} "{{.Device}}"

# Create mountpoint
mkdir -p "{{.MountPoint}}"
chmod a+rw "{{.MountPoint}}"

# Configure fstab
echo "{{.Device}} {{.MountPoint}} {{.FileSystem}} defaults 0 2" >>/etc/fstab

# Mounts device
mount -a
