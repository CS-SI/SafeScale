#!/usr/bin/env bash

/usr/local/bin/umount-{{.Container}}
echo "umount : $?" > /tmp/umount.log

rm /etc/s3ql/auth.{{.Container}}
echo "rm auth : $?" >> /tmp/umount.log
rm /usr/local/bin/mount-{{.Container}}
echo "rm mount : $?" >> /tmp/umount.log
rm /usr/local/bin/umount-{{.Container}}
echo "rm umount : $?" >> /tmp/umount.log
