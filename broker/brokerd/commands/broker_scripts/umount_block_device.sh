#!/usr/bin/env bash

#umount the device
umount {{.Device}}

#Retrieve mount point from fstab
mountpoint=`grep -e "^{{.Device}}" /etc/fstab |awk '{print $2;}'`

#Remove line in fstab
sed -i '\#^{{.Device}}#d' /etc/fstab

#Remove mount directory*
if [ "${mountpoint}" != "/" ]
then
	rm -rf ${mountpoint}
fi
