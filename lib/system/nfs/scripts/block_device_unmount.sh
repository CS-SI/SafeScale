#!/usr/bin/env bash
#
# Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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
# block_device_unmount.sh
# Unmount a block device and removes the corresponding entry from /etc/fstab

{{.BashHeader}}

function print_error() {
  ec=$?
  read line file <<< $(caller)
  echo "An error occurred in line $line of file $file (exit code $ec) :" "{"$(sed "${line}q;d" "$file")"}" >&2
}
trap print_error ERR

eval "$(lsblk -P -o MOUNTPOINT /dev/disk/by-uuid/{{.UUID}})"
[ -z "$MOUNTPOINT" ] && echo "device /dev/disk/by-uuid/{{.UUID}} not mounted" && exit 0

umount -l -f "$MOUNTPOINT" && sed -i '\:{{.UUID}}:d' /etc/fstab
