#!/usr/bin/env bash
#
# Copyright 2015-2018 CS Systemes d'Information
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

# Unmounts filesystem
umount -l -f "{{.Device}}"

# Removes entry from fstab
sed -i '\#^{{.Device}}#d' /etc/fstab

# Removes mount point
# Mount point directory is not deleted as it might contain data
# rmdir -f "{{.MountPoint}}"
