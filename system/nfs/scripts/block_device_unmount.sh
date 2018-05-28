#!/usr/bin/env bash
#
# block_device_unmount.sh
# Unmount a block device and removes the corresponding entry from /etc/fstab

# Unmounts filesystem
umount -l -f "{{.Device}}"

# Removes entry from fstab
sed -i '\#^{{.Device}}#d' /etc/fstab

# Removes mount point
# Mount point directory is not deleted as it might contain data
# rmdir -f "{{.MountPoint}}"