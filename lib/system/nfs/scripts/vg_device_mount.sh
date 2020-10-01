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
# vg_device_mount.sh
# Creates a LVM VG on a filesystem and mounts it

set -u -o pipefail

function print_error {
    read line file <<<$(caller)
    echo "An error occurred in line $line of file $file:" "{"`sed "${line}q;d" "$file"`"}" >&2
}
trap print_error ERR

{{if .DoNotFormat}}
sudo mkdir -p /data/{{.Name}} || true
sudo vgimport {{.Name}}VG
sudo vgchange -ay {{.Name}}VG
sudo mount /dev/{{.Name}}VG/{{.Name}} /data/{{.Name}}
sudo pvdisplay -C -o vg_name,pv_uuid | grep {{.Name}}VG | awk {'print "SS:MOUNTEDPV:"$2'}
sudo lvdisplay {{.Name}}VG | grep UUID | awk '{print "SS:MOUNTEDLV:"$3}'
{{else}}
sudo sed -i '\:{{.Name}}_lvm_:d' /etc/fstab > /dev/null 2>&1
{{block "list" .Drives}}{{"\n"}}{{range .}}{{println "sudo umount" . "&& sudo pvcreate" . "-f > /dev/null 2>&1"}}{{end}}{{end}}
sudo vgcreate {{.Name}}VG {{block "ali" .Drives}}{{range .}}{{ . }} {{end}}{{end}} > /dev/null 2>&1
sudo lvcreate -l 100%FREE -n {{.Name}} {{.Name}}VG > /dev/null 2>&1
sudo mkfs -t {{.FileSystem}} /dev/{{.Name}}VG/{{.Name}} > /dev/null 2>&1
sudo mkdir -p /data/{{.Name}}
sudo mount /dev/{{.Name}}VG/{{.Name}} /data/{{.Name}}
sudo rmdir /data/{{.Name}}_lvm_* || true
sudo chown -R gpac:gpac /data/{{.Name}}

{{block "uids" .Drives}}{{"\n"}}{{range .}}{{println "sudo pvdisplay" . "2>/dev/null | grep UUID | awk '{print \"SS:MOUNTEDPV:\"$3}'"}}{{end}}{{end}}
sudo vgdisplay {{.Name}}VG 2>/dev/null | grep UUID | awk '{print "SS:MOUNTEDVG:"$3}'
{{end}}