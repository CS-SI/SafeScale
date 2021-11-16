#!/usr/bin/env bash
#
# Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# block_device_mount.sh
# Creates a filesystem on a device and mounts it

{{.BashHeader}}

print_error() {
    ec=$?
    read line file <<<$(caller)
    echo "An error occurred in line $line of file $file (exit code $ec) :" "{"$(sed "${line}q;d" "$file")"}" >&2
}

trap print_error ERR

UUID=""
{{- if not .DoNotFormat }}
mkfs -F -t {{.FileSystem}} "{{.Device}}" >/dev/null || {
    echo "failed to format" && exit 2
}
{{- end }}

# define UUID variable
eval $(blkid | grep "{{.Device}}" | cut -d: -f2-)
[ "$UUID" = "" ] && {
	echo "failed to get UUID of new device"
	exit 1
}

cp /etc/fstab /tmp/fstab.sav.$$ && \
echo "/dev/disk/by-uuid/$UUID {{.MountPoint}} {{.FileSystem}} defaults 0 2" >>/etc/fstab && \
mkdir -p "{{.MountPoint}}" >/dev/null && \
mount {{.MountPoint}} >/dev/null && \
chmod a+rwx "{{.MountPoint}}" >/dev/null && \
echo -n $UUID && \
rm -f /tmp/fstab.sav.$$ && \
exit 0

# If we arrive here, issue happened, restore fstab
mv /tmp/fstab.sav.$$ /etc/fstab
exit 1
