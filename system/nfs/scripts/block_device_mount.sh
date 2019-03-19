#!/usr/bin/env bash
#
# Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

function print_error {
    read line file <<<$(caller)
    echo "An error occurred in line $line of file $file:" "{"`sed "${line}q;d" "$file"`"}" >&2
}
trap print_error ERR

UUID=""
{{- if not .DoNotFormat }}
mkfs -F -t {{.FileSystem}} "{{.Device}}" >/dev/null
{{- end }}
eval $(blkid | grep "{{.Device}}" | cut -d: -f2-)

echo "/dev/disk/by-uuid/$UUID {{.MountPoint}} {{.FileSystem}} defaults 0 2" >>/etc/fstab && \
mkdir -p "{{.MountPoint}}" >/dev/null && \
mount {{.MountPoint}} >/dev/null && \
chmod a+rwx "{{.MountPoint}}" >/dev/null && \
echo -n $UUID && exit 0

exit 1
