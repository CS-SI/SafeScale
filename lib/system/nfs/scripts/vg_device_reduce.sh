#!/usr/bin/env bash
#
# Copyright 2018, CS Systemes d'Information, http://csgroup.eu
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

set -u -o pipefail

function print_error {
    read line file <<<$(caller)
    echo "An error occurred in line $line of file $file:" "{"`sed "${line}q;d" "$file"`"}" >&2
}
trap print_error ERR

MINSIZE=$(sudo resize2fs -P /dev/mapper/{{.Name}}VG-{{.Name}}  | grep "minimum size" | awk {'print $NF-1'})
let "mingb = 4 * $MINSIZE / 1024 / 1024 + 1"
if [[ {{.TargetSize}} -lt $mingb ]]
then
echo "SS:FAILURE:Cannot be done, not enough space available, $mingb Gb is the minimum size"
exit 1
fi

sudo umount -l -f /dev/mapper/{{.Name}}VG-{{.Name}} || true
sudo e2fsck -f -y /dev/mapper/{{.Name}}VG-{{.Name}}
let "x = 4 * $MINSIZE / 1024 / 1024 + 1"
let "y = (x < {{.VUSize}}) ? {{.VUSize}} : x"
let "z = y * 1020"
sudo resize2fs -p /dev/mapper/{{.Name}}VG-{{.Name}} ${z}M || true
sudo e2fsck -f -y /dev/mapper/{{.Name}}VG-{{.Name}}
sudo lvreduce -y -f -L ${z}M /dev/mapper/{{.Name}}VG-{{.Name}}

DRIVES=$(sudo pvs --noheadings | grep {{.Name}}VG | awk {'print $1'})
for d in $DRIVES; do
    res=$(sudo pvdisplay ${d} | grep "Allocated PE" | grep " 0") || true
    if [ ! -z "$res" ]; then
        sudo pvmove ${d} || true
        sudo pvdisplay ${d} | grep "PV UUID" | awk {'print "SS:DELETED:"$3'} | tr '\n' ':'  && echo ${d}
        sudo vgreduce {{.Name}}VG ${d}
        sudo pvremove ${d}
    fi
done

sudo mount /dev/mapper/{{.Name}}VG-{{.Name}} /data/{{.Name}}
