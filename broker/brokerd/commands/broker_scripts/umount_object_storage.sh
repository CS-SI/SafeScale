#!/usr/bin/env bash

echo "{{.Password}}" |sudo umount.s3ql {{.MountPoint}}

rm /etc/s3ql/auth.{{.Container}}
rm /usr/loca/bin/mount-{{.Container}}
rm /usr/loca/bin/umount-{{.Container}}
