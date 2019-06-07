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
# nfs_client_share_mount.sh
#
# Declares a remote share mount and mount it

{{.BashHeader}}

function print_error {
    read line file <<<$(caller)
    echo "An error occurred in line $line of file $file:" "{"`sed "${line}q;d" "$file"`"}" >&2
}
trap print_error ERR

mkdir -p "{{.MountPoint}}" && \
echo mount.nfs -o {{ .cacheOption }} "{{.Export}}" "{{.MountPoint}}" > /opt/safescale/var/tmp/moco.txt && \
mount.nfs -o {{ .cacheOption }} "{{.Export}}" "{{.MountPoint}}" && \
echo "{{.Export}} {{.MountPoint}}   nfs defaults,user,auto,noatime,intr,{{ .cacheOption }} 0   0" >>/etc/fstab
