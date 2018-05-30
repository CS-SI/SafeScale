#!/usr/bin/env bash
#
# Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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
# nfs_server_install.sh
#
# Installs and configures a NFS Server service

{{.CommonTools}}

echo "Install NFS server"

case $LINUX_KIND in
    debian|ubuntu)
        export DEBIAN_FRONTEND=noninteractive
        touch /var/log/lastlog
        chgrp utmp /var/log/lastlog
        chmod 664 /var/log/lastlog

        # VPL: I encountered the case where apt is locked between update and install... (!)
        wait_for_apt && apt-get update && wait_for_apt && apt-get install -qqy nfs-common nfs-kernel-server
        ;;

    rhel|centos)
        yum make-cache fast
        yum install -y nfs-kernel-server nfs-common
        ;;

    *)
        echo "Unsupported operating system '$LINUX_KIND'"
        exit 1
        ;;
esac
exit 0
