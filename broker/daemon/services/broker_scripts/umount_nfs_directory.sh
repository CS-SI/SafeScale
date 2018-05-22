#!/usr/bin/env bash

#umount the device
umount {{.NFSServer}}:{{.ExportedPath}}

#Remove line in fstab
sed -i '\#^{{.NFSServer}}:{{.ExportedPath}}#d' /etc/fstab
