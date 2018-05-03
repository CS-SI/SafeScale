#!/usr/bin/env bash
#
# block_device_unmount.sh
# Unmount a block device and removes the corresponding entry from /etc/fstab

# Unmounts filesystem
umount -l -f "{{.MountPoint}}"

# Removes entry from fstab
grep -v "^{{.Device}} {{.MountPoint}}" /etc/fstab >/etc/fstab.new
mv /etc/fstab.new /etc/fstab

# Removes mount point
rmdir -f "{{.MountPoint}}"