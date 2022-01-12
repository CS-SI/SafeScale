#!/usr/bin/env bash
#
# Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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
# bucket_mount.sh
#
# Declares a bucket mount in fstab and mount it

{{.BashHeader}}

function print_error() {
  ec=$?
  read line file <<< $(caller)
  echo "An error occurred in line $line of file $file (exit code $ec) :" "{"$(sed "${line}q;d" "$file")"}" >&2
}
trap print_error ERR

echo "{{ .BucketName }}:{{ .BucketName }} {{ .MountPoint }} rclone rw,auto,nofail,args2env,vfs_cache_mode=writes,config={{ .ConfigFile }},cache_dir=/var/cache/rclone,allow-root,allow-other 0 0" >>/etc/fstab
mkdir -p "{{.MountPoint}}"
chown {{.OperatorUsername}}:{{.OperatorUsername}} "{{.MountPoint}}"
chmod 777 "{{.MountPoint}}"
mount "{{ .MountPoint }}"
